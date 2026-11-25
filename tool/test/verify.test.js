import { test, before, after } from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto"
import { verify } from "../src/verify.js"

// a tiny app with one route of each kind; tokens "token-a" (owner of note 1) and "token-b"
const TOKENS = { "Bearer token-a": "a", "Bearer token-b": "b" }
const NOTES = { 1: { id: 1, owner: "a", text: "a's note" } }

const server = http.createServer((req, res) => {
	const user = TOKENS[req.headers.authorization]
	const send = (status, body) => {
		res.writeHead(status, { "content-type": "application/json" })
		res.end(JSON.stringify(body))
	}
	const [, , id] = req.url.split("/")
	if (req.method === "POST" && req.url === "/login") {
		let raw = ""
		req.on("data", chunk => (raw += chunk))
		req.on("end", () => {
			const { name } = JSON.parse(raw)
			send(200, { auth: { token: `token-${name}` } })
		})
		return
	}
	if (req.url.startsWith("/leaky/")) return user ? send(200, NOTES[id]) : send(401, {})
	if (req.url.startsWith("/scoped/")) return user ? (NOTES[id]?.owner === user ? send(200, NOTES[id]) : send(404, {})) : send(401, {})
	if (req.url.startsWith("/open/")) return send(200, { id, title: "public" })
	if (req.url.startsWith("/forgot-auth/")) return send(200, NOTES[id])
	if (req.url.startsWith("/achievements/")) return user ? send(200, { userId: id, courses: [], paths: [] }) : send(401, {})
	if (req.url === "/admin/stats") return user ? send(200, { users: 2, at: Date.now() }) : send(401, {})
	if (req.url === "/admin/protected") return user === "a" ? send(200, {}) : send(403, {})
	send(404, {})
})

let baseUrl
before(async () => {
	await new Promise(resolve => server.listen(0, "127.0.0.1", resolve))
	baseUrl = `http://127.0.0.1:${server.address().port}`
})
after(() => server.close())

const route = (method, path, auth = true, role = false) => ({ method, path, auth, role })
const routes = [
	route("GET", "/leaky/:id"),
	route("GET", "/scoped/:id"),
	route("GET", "/open/:id", false),
	route("GET", "/forgot-auth/:id"),
	route("GET", "/admin/stats"),
	route("GET", "/admin/protected"),
	route("GET", "/needs/:other"),
	route("GET", "/achievements/:id"),
	route("DELETE", "/leaky/:id")
]
const findings = [
	{ rule: "BFLA", route: "GET /admin/stats" },
	{ rule: "BFLA", route: "GET /admin/protected" }
]
const config = {
	users: {
		owner: { headers: { authorization: "Bearer token-a" } },
		other: { login: { path: "/login", body: { name: "b" }, token: "auth.token" } }
	},
	params: { id: "1" }
}

const run = async (options = {}) => {
	const results = await verify({ routes, findings, baseUrl, config, ...options })
	return Object.fromEntries(results.map(r => [r.route, r]))
}

test("another user reading the owner's record is confirmed", async () => {
	const results = await run()
	assert.equal(results["GET /leaky/:id"].verdict, "CONFIRMED")
	assert.match(results["GET /leaky/:id"].reason, /another user got the owner's data/)
})

test("a record the second user cannot read is protected", async () => {
	assert.equal((await run())["GET /scoped/:id"].verdict, "PROTECTED")
})

test("a route the code leaves open is public, not a finding", async () => {
	assert.equal((await run())["GET /open/:id"].verdict, "PUBLIC")
})

test("a route whose code expects a login but answers anonymously is confirmed", async () => {
	assert.match((await run())["GET /forgot-auth/:id"].reason, /expects a login/)
})

test("an operator route an ordinary user reaches is confirmed, even when its answer changes per call", async () => {
	const results = await run()
	assert.equal(results["GET /admin/stats"].verdict, "CONFIRMED")
	assert.equal(results["GET /admin/protected"].verdict, "PROTECTED")
})

test("two identical empty answers are inconclusive, not a leak", async () => {
	const result = (await run())["GET /achievements/:id"]
	assert.equal(result.verdict, "INCONCLUSIVE")
	assert.match(result.reason, /same empty answer/)
})

test("a route with a parameter the config does not fill is skipped", async () => {
	assert.equal((await run())["GET /needs/:other"].verdict, "SKIPPED")
})

test("writes are replayed only when allowed", async () => {
	assert.equal((await run())["DELETE /leaky/:id"], undefined)
})

// a DPoP app: a two-step login (password, then a code), tokens bound to the client's key

const bound = new Map()
const checkProof = (req, path, accessToken) => {
	const [h, p, s] = String(req.headers.dpop ?? "").split(".")
	if (!s) return null
	const header = JSON.parse(Buffer.from(h, "base64url"))
	const payload = JSON.parse(Buffer.from(p, "base64url"))
	const key = createPublicKey({ key: header.jwk, format: "jwk" })
	const ok = verifySignature("sha256", Buffer.from(`${h}.${p}`), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"))
	if (!ok || header.typ !== "dpop+jwt" || payload.htm !== req.method || payload.htu !== `https://app.example${path}`) return null
	if (accessToken && payload.ath !== createHash("sha256").update(accessToken).digest("base64url")) return null
	return `${header.jwk.x}.${header.jwk.y}`
}
const dpopServer = http.createServer((req, res) => {
	let raw = ""
	req.on("data", c => (raw += c))
	req.on("end", () => {
		const send = (status, body) => {
			res.writeHead(status, { "content-type": "application/json" })
			res.end(JSON.stringify(body))
		}
		const body = raw ? JSON.parse(raw) : {}
		if (req.url === "/auth/login") return send(200, { data: { login_token: `lt-${body.email}` } })
		if (req.url === "/auth/login/verify") {
			const jkt = checkProof(req, req.url)
			if (!jkt || body.otp !== "123456") return send(401, {})
			const token = `at-${body.login_token}`
			bound.set(token, jkt)
			return send(200, { data: { access_token: token } })
		}
		const [scheme, token] = String(req.headers.authorization ?? "").split(" ")
		const jkt = scheme === "DPoP" ? checkProof(req, req.url, token) : null
		if (!jkt || bound.get(token) !== jkt) return send(401, {})
		send(200, { note: 1, text: "a's note" })
	})
})

test("DPoP users sign in through a two-step login and send a valid proof on every request", async () => {
	await new Promise(resolve => dpopServer.listen(0, "127.0.0.1", resolve))
	const url = `http://127.0.0.1:${dpopServer.address().port}`
	const login = email => ({
		dpop: true,
		login: [
			{ path: "/auth/login", body: { email, password: "x" }, save: { lt: "data.login_token" } },
			{ path: "/auth/login/verify", body: { login_token: "{{lt}}", otp: "{{prompt:code}}" }, token: "data.access_token" }
		]
	})
	const asked = []
	try {
		const results = await verify({
			routes: [{ method: "GET", path: "/notes/:id", auth: true, role: false }],
			findings: [],
			baseUrl: url,
			config: { dpopOrigin: "https://app.example", users: { owner: login("a"), other: login("b") }, params: { id: "1" } },
			ask: async label => (asked.push(label), "123456")
		})
		assert.deepEqual(asked, ["code", "code"])
		assert.deepEqual(results[0].status, { owner: 200, other: 200, anonymous: 401 })
		assert.equal(results[0].verdict, "CONFIRMED")
	} finally {
		dpopServer.close()
	}
})
