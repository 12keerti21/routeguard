import { test, before, after } from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { verify } from "../src/verify.js"

// an app where each user lists their own notes, a team list both users share, and nested comments
const TOKENS = { "Bearer a": "a", "Bearer b": "b" }
const server = http.createServer((req, res) => {
	const user = TOKENS[req.headers.authorization]
	const send = (status, body) => {
		res.writeHead(status, { "content-type": "application/json" })
		res.end(JSON.stringify(body))
	}
	if (!user) return send(401, {})
	const parts = req.url.split("/").filter(Boolean)
	if (req.url === "/notes") return send(200, { data: user === "a" ? [{ id: "n1", title: "a's" }] : [{ id: "n2", title: "b's" }] })
	if (parts[0] === "notes" && parts.length === 2) return send(200, { id: parts[1], text: `note ${parts[1]}` })
	if (parts[0] === "notes" && parts[2] === "comments" && parts.length === 3)
		return send(200, user === "a" ? { items: [{ commentId: "c1" }] } : { items: [] })
	if (parts[2] === "comments" && parts.length === 4) return send(200, { commentId: parts[3], body: "a's comment" })
	if (req.url === "/teams") return send(200, { page: 1, results: [{ teamId: "t1", name: "everyone" }] })
	if (parts[0] === "teams" && parts.length === 2) return send(200, { teamId: parts[1], name: "everyone" })
	send(404, {})
})

let baseUrl
before(async () => {
	await new Promise(resolve => server.listen(0, "127.0.0.1", resolve))
	baseUrl = `http://127.0.0.1:${server.address().port}`
})
after(() => server.close())

const route = (method, path) => ({ method, path, auth: true, role: false })
const routes = [
	route("GET", "/notes"),
	route("GET", "/notes/:id"),
	route("GET", "/notes/:id/comments"),
	route("GET", "/notes/:id/comments/:commentId"),
	route("GET", "/teams"),
	route("GET", "/teams/:teamId")
]
const config = { users: { owner: { headers: { authorization: "Bearer a" } }, other: { headers: { authorization: "Bearer b" } } } }

test("ids come from the owner's own list, never one the other user also sees", async () => {
	const results = await verify({ routes, findings: [], baseUrl, config })
	const found = Object.fromEntries(results.discovered.map(d => [d.param, d]))
	assert.equal(found.id.value, "n1")
	assert.equal(found.id.ownerOnly, true)
	assert.equal(results.find(r => r.route === "GET /notes/:id").verdict, "CONFIRMED")
})

test("nested ids are found once the parent id is known", async () => {
	const results = await verify({ routes, findings: [], baseUrl, config })
	assert.equal(results.discovered.find(d => d.param === "commentId")?.value, "c1")
	assert.equal(results.find(r => r.route === "GET /notes/:id/comments/:commentId").verdict, "CONFIRMED")
})

test("a record both users can list is not reported as a leak", async () => {
	const results = await verify({ routes, findings: [], baseUrl, config })
	const team = results.find(r => r.route === "GET /teams/:teamId")
	assert.equal(team.verdict, "INCONCLUSIVE")
	assert.match(team.reason, /also list :teamId/)
})

test("ids in the config win, and discovery can be turned off", async () => {
	const results = await verify({ routes, findings: [], baseUrl, config: { ...config, params: { id: "n9" }, discover: false } })
	assert.equal(results.discovered.length, 0)
	assert.equal(results.find(r => r.route === "GET /notes/:id").path, "/notes/n9")
})
