import { test } from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { mapRoutes } from "../src/mapper.js"
import { bola } from "../src/rules/bola.js"
import { bfla } from "../src/rules/bfla.js"
import { massAssignment } from "../src/rules/massAssignment.js"
import { ssrf } from "../src/rules/ssrf.js"
import { rateLimit } from "../src/rules/rateLimit.js"
import { dataExposure } from "../src/rules/dataExposure.js"

const app = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/app")
const routes = mapRoutes(app)

const route = (method, routePath) => {
	const found = routes.find(r => r.method === method && r.path === routePath)
	assert.ok(found, `route ${method} ${routePath} not mapped`)
	return found
}

test("mapper joins mount prefixes and finds every route", () => {
	assert.equal(routes.filter(r => r.path.startsWith("/api/notes")).length, 8)
	assert.equal(routes.filter(r => r.path.startsWith("/api/users")).length, 4)
})

test("mapper keeps the prefix of a router built and mounted in the same file", () => {
	assert.ok(route("POST", "/v2/signup"))
})

test("mapper carries mount-level middleware into the router's routes", () => {
	assert.deepEqual(route("GET", "/api/private").middleware, ["auth"])
	assert.equal(route("GET", "/api/private").auth, true)
	assert.equal(route("GET", "/api/notes").auth, false)
})

test("mapper reads [auth, admin] as a role check", () => {
	const r = route("DELETE", "/api/notes/:id")
	assert.deepEqual(r.middleware, ["auth", "admin"])
	assert.equal(r.role, true)
})

test("BOLA flags an id lookup that ignores the caller", () => {
	const finding = bola(route("GET", "/api/notes/:id"))
	assert.equal(finding?.rule, "BOLA")
	assert.equal(finding.severity, "MEDIUM")
})

test("BOLA passes a lookup scoped to req.user, via a destructured id", () => {
	assert.equal(bola(route("GET", "/api/notes/mine/:id")), null)
})

test("BOLA passes a route behind a role check", () => {
	assert.equal(bola(route("DELETE", "/api/notes/:id")), null)
})

test("BFLA flags an operator path without a role check", () => {
	const finding = bfla(route("GET", "/api/users/admin/stats"))
	assert.equal(finding?.severity, "HIGH")
})

test("BFLA flags a shared-record write, passes one owned by the caller", () => {
	assert.equal(bfla(route("POST", "/api/notes/pinned"))?.severity, "MEDIUM")
	assert.equal(bfla(route("POST", "/api/notes")), null)
})

test("mass assignment flags the whole body into a user model", () => {
	const finding = massAssignment(route("POST", "/api/users"))
	assert.equal(finding?.severity, "HIGH")
	assert.match(finding.message, /new User/)
})

test("mass assignment flags isAdmin copied from the body", () => {
	assert.match(massAssignment(route("POST", "/api/users/signup"))?.message ?? "", /isAdmin/)
})

test("mass assignment passes picked fields", () => {
	assert.equal(massAssignment(route("POST", "/api/users/invite")), null)
})

test("path-scoped app.use guards apply, and isAuthorized() is auth, not a role", () => {
	const r = route("GET", "/rest/basket/:id")
	assert.equal(r.auth, true)
	assert.equal(r.role, false)
})

test("BOLA follows a handler factory and ignores identity read off the query path", () => {
	assert.equal(bola(route("GET", "/rest/basket/:id"))?.rule, "BOLA")
})

test("BOLA passes a query scoped by an identity helper's result", () => {
	assert.equal(bola(route("DELETE", "/rest/cards/:id")), null)
})

test("BOLA passes a handler that checks the role inline", () => {
	assert.equal(bola(route("DELETE", "/rest/baskets/:id")), null)
})

test("handlers imported through package.json subpath imports are read", () => {
	assert.equal(bola(route("GET", "/api/notes/reports/:id"))?.rule, "BOLA")
})

test("BOLA follows the caller into a service that never uses it", () => {
	const finding = bola(route("GET", "/api/courses/:courseId"))
	assert.equal(finding?.rule, "BOLA")
	assert.match(finding.where, /services\/course\.service\.js:5$/)
	assert.match(finding.message, /via getCourse/)
})

test("BOLA passes a service whose owner check sits two calls down, through destructured arguments", () => {
	assert.equal(bola(route("PUT", "/api/courses/:courseId")), null)
})

test("BOLA passes reading a parent to create the caller's own record", () => {
	assert.equal(bola(route("POST", "/api/courses/:courseId/reviews")), null)
})

test("BOLA still flags an unscoped delete next to the caller's own record", () => {
	const finding = bola(route("POST", "/api/courses/:courseId/checkout"))
	assert.equal(finding?.rule, "BOLA")
	assert.match(finding.message, /^destroy/)
})

test("a routeguard-ignore comment marks the route's suppressed rules", () => {
	const r = route("GET", "/api/notes/shared/:shareId")
	assert.ok(r.ignored.has("BOLA"))
	assert.equal(route("GET", "/api/notes/:id").ignored, null)
})

test("SSRF flags a client-chosen URL as HIGH", () => {
	assert.equal(ssrf(route("POST", "/int/preview"))?.severity, "HIGH")
})

test("SSRF rates a parameter inside a fixed host's URL as MEDIUM", () => {
	assert.equal(ssrf(route("GET", "/int/weather"))?.severity, "MEDIUM")
})

test("SSRF passes a URL checked against an allow-list", () => {
	assert.equal(ssrf(route("POST", "/int/webhook-test")), null)
})

test("rate limit flags an unlimited login and passes a limited one", () => {
	assert.equal(rateLimit(route("POST", "/int/login"))?.rule, "RATE_LIMIT")
	assert.equal(rateLimit(route("POST", "/int/login-limited")), null)
})

test("rate limit flags a code check behind a session, not a signed-in password change", () => {
	assert.equal(rateLimit(route("POST", "/int/otp-verify"))?.rule, "RATE_LIMIT")
	assert.equal(rateLimit(route("POST", "/int/change-password")), null)
})

test("data exposure flags a whole user record sent through .then", () => {
	assert.equal(dataExposure(route("GET", "/int/people/:id"))?.rule, "DATA_EXPOSURE")
})

test("data exposure passes a query that selects fields", () => {
	assert.equal(dataExposure(route("GET", "/int/people/:id/card")), null)
})

test("no rule fires on the public list route", () => {
	const r = route("GET", "/api/notes")
	assert.deepEqual([bola(r), bfla(r), massAssignment(r), ssrf(r), rateLimit(r), dataExposure(r)], [null, null, null, null, null, null])
})
