import { test, after } from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { createHmac } from "node:crypto"
import { verify } from "../src/verify.js"

const b64 = v => Buffer.from(JSON.stringify(v)).toString("base64url")
const sign = data => createHmac("sha256", "probe-test").update(data).digest("base64url")
const jwt = payload => {
	const head = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}`
	return `${head}.${sign(head)}`
}
const TOKEN_A = jwt({ sub: "a" })
const TOKEN_B = jwt({ sub: "b" })

// careless: reads the JWT without checking it, echoes any origin with credentials, names Express,
// returns password hashes, prints stack traces, keeps a debug route, never limits logins and fetches any URL
// careful: the opposite on every count
function app(careful) {
	return http.createServer((req, res) => {
		const send = (status, body, extra = {}) => {
			const headers = { "content-type": "application/json", ...extra }
			if (careful) headers["x-content-type-options"] = "nosniff"
			else headers["x-powered-by"] = "Express"
			if (!careful && req.headers.origin) Object.assign(headers, { "access-control-allow-origin": req.headers.origin, "access-control-allow-credentials": "true" })
			res.writeHead(status, headers)
			res.end(typeof body === "string" ? body : JSON.stringify(body))
		}
		const token = String(req.headers.authorization ?? "").replace("Bearer ", "")
		const [head, payload, signature] = token.split(".")
		let user = null
		try {
			const claims = JSON.parse(Buffer.from(payload, "base64url"))
			if (!careful || sign(`${head}.${payload}`) === signature) user = claims.sub
		} catch {}
		let raw = ""
		req.on("data", chunk => (raw += chunk))
		req.on("end", async () => {
			const body = !raw ? {} : req.headers["content-type"] === "application/json" ? JSON.parse(raw) : Object.fromEntries(new URLSearchParams(raw))
			if (req.url === "/login") return careful && ++attempts[careful] > 5 ? send(429, {}, { "retry-after": "60" }) : send(401, { error: "wrong password" })
			if (req.url === "/debug/env") return careful ? send(404, {}) : send(200, { env: "dev" })
			if (req.url === "/avatar") {
				if (!user) return send(401, {})
				if (!careful) await fetch(body.imageUrl).catch(() => {})
				return send(200, {})
			}
			const [, , id] = req.url.split("/")
			if (req.url.startsWith("/users/")) {
				if (!user) return send(401, {})
				if (!/^\w+$/.test(id)) return careful ? send(400, { error: "bad id" }) : send(500, `CastError: Cast to ObjectId failed\n    at model.find (/app/node_modules/mongoose/lib/query.js:12:3)`)
				return send(200, careful ? { id, name: "A" } : { id, name: "A", passwordHash: "$2b$10$abc" })
			}
			send(404, {})
		})
	})
}
const attempts = { true: 0 }

const route = (method, path, auth = true) => ({ method, path, auth, role: false })
const routes = [route("GET", "/users/:id"), route("GET", "/debug/env", false), route("POST", "/login", false), route("POST", "/avatar")]
const findings = [
	{ rule: "NON_PROD_ROUTE", route: "GET /debug/env" },
	{ rule: "RATE_LIMIT", route: "POST /login" },
	{ rule: "SSRF", route: "POST /avatar", severity: "HIGH", input: { in: "body", name: "imageUrl" } }
]
const config = {
	users: { owner: { headers: { authorization: `Bearer ${TOKEN_A}` } }, other: { headers: { authorization: `Bearer ${TOKEN_B}` } } },
	params: { id: "a" },
	discover: false
}

const servers = []
async function probe(careful) {
	const server = app(careful)
	servers.push(server)
	await new Promise(resolve => server.listen(0, "127.0.0.1", resolve))
	const results = await verify({
		routes,
		findings,
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		config,
		probeOptions: { rateLimits: true, ssrf: true, attempts: 8 }
	})
	return Object.fromEntries(results.filter(r => r.probe).map(r => [r.probe, r]))
}
after(() => servers.forEach(s => s.close()))

test("probes confirm each weakness on a careless app", async () => {
	const results = await probe(false)
	for (const probe of ["CORS", "SECURITY_HEADERS", "DATA_EXPOSURE", "ERROR_LEAK", "JWT", "NON_PROD_ROUTE", "RATE_LIMIT", "SSRF"])
		assert.equal(results[probe]?.verdict, "CONFIRMED", `${probe}: ${results[probe]?.reason}`)
	assert.match(results.DATA_EXPOSURE.reason, /passwordHash/)
	assert.doesNotMatch(results.DATA_EXPOSURE.reason, /\$2b/)
	assert.match(results.JWT.reason, /alg: none/)
})

test("probes find nothing on a careful app", async () => {
	const results = await probe(true)
	assert.equal(results.DATA_EXPOSURE, undefined)
	for (const probe of ["CORS", "SECURITY_HEADERS", "ERROR_LEAK", "JWT", "NON_PROD_ROUTE", "RATE_LIMIT"])
		assert.equal(results[probe]?.verdict, "PROTECTED", `${probe}: ${results[probe]?.reason}`)
	assert.equal(results.SSRF.verdict, "INCONCLUSIVE")
})
