import { test } from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { mapRoutes } from "../src/mapper.js"
import { bola } from "../src/rules/bola.js"
import { bfla } from "../src/rules/bfla.js"
import { misconfig } from "../src/rules/misconfig.js"

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/express-extra")
const routes = mapRoutes(root)
const byRoute = new Map(routes.map(r => [`${r.method} ${r.path}`, r]))
const findings = [...routes.flatMap(r => [bola, bfla].map(rule => rule(r)).filter(Boolean)), ...misconfig(root)]
const find = (rule, route) => findings.find(f => f.rule === rule && f.route === route)

test("HTTP client calls are not routes, a route in a return statement is", () => {
	assert.ok(![...byRoute.keys()].some(k => k.includes("/admin/")), "client.get(url, config) in a frontend service")
	assert.ok(byRoute.has("GET /university/*"), "return webRouter.get(path, handler)")
})

test("an auth middleware factory with a scope counts as a role check", () => {
	const route = byRoute.get("POST /internal/credentials/resolve")
	assert.equal(route.auth, true)
	assert.equal(route.role, true)
	assert.equal(find("BFLA", "POST /internal/credentials/resolve"), undefined)
})

test("public handshakes, metrics, HEAD reads and random UUIDs", () => {
	assert.equal(find("BFLA", "GET /system/ping"), undefined)
	assert.equal(find("BFLA", "GET /metrics").severity, "MEDIUM")
	assert.equal(find("BOLA", "HEAD /items/:id"), undefined, "HEAD is a read, like GET")
	assert.equal(find("BOLA", "DELETE /api/uploads/:uuid").severity, "MEDIUM")
})

test("CORS used only in development, and * with credentials, are LOW", () => {
	const cors = findings.filter(f => f.rule === "CORS")
	assert.equal(cors.length, 2)
	assert.ok(cors.every(f => f.severity === "LOW"))
	assert.ok(cors.some(f => /development/.test(f.message)))
	assert.ok(cors.some(f => /browsers refuse/.test(f.message)))
})
