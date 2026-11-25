import { test, before, after } from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
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

test("a route with a parameter the config does not fill is skipped", async () => {
	assert.equal((await run())["GET /needs/:other"].verdict, "SKIPPED")
})

test("writes are replayed only when allowed", async () => {
	assert.equal((await run())["DELETE /leaky/:id"], undefined)
})
