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
import { misconfig } from "../src/rules/misconfig.js"
import { inventory } from "../src/rules/inventory.js"
import { businessFlow } from "../src/rules/businessFlow.js"
import { consumption } from "../src/rules/consumption.js"

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

const appWide = misconfig(app)
const inventoried = inventory(routes, app)
const atFile = (findings, rule, file) => findings.filter(f => f.rule === rule && f.where.startsWith(file))

test("misconfig flags CORS that reflects any origin with credentials, not a fixed list", () => {
	const cors = atFile(appWide, "CORS", "config.js")
	assert.equal(cors.length, 1)
	assert.equal(cors[0].severity, "HIGH")
})

test("misconfig flags JWT algorithm confusion and a key in the code", () => {
	const jwt = atFile(appWide, "JWT", "config.js").map(f => f.message)
	assert.ok(jwt.some(m => /algorithm confusion/.test(m)))
	assert.ok(jwt.some(m => /key written in the code/.test(m)))
})

test("misconfig flags a stack trace in an error response", () => {
	assert.equal(atFile(appWide, "ERROR_LEAK", "config.js")[0]?.severity, "MEDIUM")
})

test("misconfig flags an app without security headers once", () => {
	assert.equal(appWide.filter(f => f.rule === "SECURITY_HEADERS").length, 1)
})

test("inventory flags a v1 copy of an endpoint that drops its auth", () => {
	const shadow = inventoried.find(f => f.rule === "SHADOW_ROUTE")
	assert.equal(shadow?.route, "GET /api/v1/notes/:id")
})

test("inventory flags a development endpoint", () => {
	assert.ok(inventoried.some(f => f.rule === "NON_PROD_ROUTE" && f.route === "GET /api/v1/dev/search"))
})

test("inventory lists routes the OpenAPI spec leaves out, not the ones it documents", () => {
	const { undocumented } = inventoried.find(f => f.rule === "UNDOCUMENTED")
	assert.ok(undocumented.includes("GET /api/users/admin/stats"))
	assert.ok(!undocumented.includes("GET /api/notes"))
	assert.ok(!undocumented.includes("GET /api/notes/:id"))
})

test("business flow flags an unguarded checkout as MEDIUM", () => {
	assert.equal(businessFlow(route("POST", "/int/checkout"))?.severity, "MEDIUM")
})

test("business flow passes a limited redemption, a catalogue and a token-gated invite", () => {
	assert.equal(businessFlow(route("POST", "/int/redeem")), null)
	assert.equal(businessFlow(route("POST", "/int/books")), null)
	assert.equal(businessFlow(route("POST", "/int/invites/:token/accept")), null)
})

const consumed = consumption(app).filter(f => f.where.startsWith("lib/weather.js"))
const consumedLines = rule => consumed.filter(f => f.rule === rule).map(f => Number(f.where.split(":")[1]))

test("consumption flags an unchecked store, eval of a response and plain http to a partner", () => {
	const unsafe = consumed.filter(f => f.rule === "UNSAFE_CONSUMPTION")
	assert.ok(unsafe.some(f => f.severity === "MEDIUM" && f.where.endsWith(":7")))
	assert.ok(unsafe.some(f => f.severity === "HIGH" && /eval/.test(f.message)))
	assert.ok(unsafe.some(f => f.severity === "LOW" && /partner\.example\.com/.test(f.message)))
})

test("consumption passes a validated store and local http", () => {
	assert.ok(!consumedLines("UNSAFE_CONSUMPTION").includes(14))
	assert.ok(!consumed.some(f => /localhost/.test(f.message)))
})

test("consumption flags an API key written into a URL", () => {
	assert.deepEqual(consumedLines("SECRET_IN_URL"), [6])
})

test("a validator named after login is not an auth check", () => {
	assert.equal(route("POST", "/int/signin").auth, false)
	assert.equal(rateLimit(route("POST", "/int/signin"))?.rule, "RATE_LIMIT")
})

test("a limiter imported by name and mounted on a path in another file covers the route", () => {
	assert.ok(route("POST", "/int/limited/login").middleware.includes("authLimiter"))
	assert.equal(rateLimit(route("POST", "/int/limited/login")), null)
})

test("paths written as constants resolve, through a template prefix and an exported object", () => {
	assert.ok(route("PUT", "/api/v3/me/history/:noteId"))
	assert.ok(route("POST", "/api/v3/me/admin/flushProjectToTpds"))
})

test("a controller written as an object method is read, and an id used inside the caller's data is scoped", () => {
	const r = route("PUT", "/api/v3/me/history/:noteId")
	assert.ok(r.fn)
	assert.equal(bola(r), null)
})

test("rate limit splits words: flushProjectToTpds holds no otp", () => {
	assert.equal(rateLimit(route("POST", "/api/v3/me/admin/flushProjectToTpds")), null)
})

test("no rule fires on the public list route", () => {
	const r = route("GET", "/api/notes")
	assert.deepEqual([bola, bfla, massAssignment, ssrf, rateLimit, dataExposure, businessFlow].map(rule => rule(r)), Array(7).fill(null))
})
