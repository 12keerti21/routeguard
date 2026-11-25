// Runtime probes for the checks beyond access control. The safe ones only read: they look at the
// answers verify already collected, or send GET requests with a foreign Origin, a malformed id or a
// doctored token. Rate limits and SSRF send requests that can have effects, so they run only when asked.
import http from "node:http"
import { randomUUID } from "node:crypto"

const OK = status => status >= 200 && status < 300
const PROBE_ORIGIN = "https://routeguard-probe.invalid"
// fields that must never reach a client; their values are never printed
const SECRET_FIELD = /^(password|passwd|password_?hash|hash(ed)?_?password|salt|secret|client_?secret|api_?key|private_?key|refresh_?token|reset_?token|otp|otp_?hash|totp_?secret|mfa_?secret|ssn)$/i
// routes that hand out tokens on purpose; only their token fields are let through
const ISSUES_TOKENS = /login|signin|sign-in|token|auth|refresh|session|verify|otp/i
// Node, Go, Python and Java stack traces, and database driver errors
const STACK_TRACE = /\n\s+at \S+.*\(?\/?[\w./-]+:\d+:\d+\)?|node_modules\/|(CastError|MongoServerError|ValidationError|SequelizeDatabaseError|QueryFailedError|PrismaClientKnownRequestError|ER_PARSE_ERROR|SyntaxError: Unexpected|goroutine \d+ \[|\.go:\d+ \+0x|Traceback \(most recent call last\)|\n\s+at [\w.$]+\([\w.]+\.java:\d+\)|pq: |SQLSTATE|sql: )/
const MALFORMED_ID = `rg'"<probe>${"9".repeat(40)}`

const result = (probe, route, verdict, reason, staticRule = null) => ({ route, staticRule, verdict, reason, probe })
const bodyOf = response => {
	try {
		return JSON.parse(response.text)
	} catch {
		return null
	}
}

// API8: does the app tell browsers that any website may read its answers, with the user's cookies?
async function cors({ answers, headers, send }) {
	const sample = answers.filter(a => a.owner && OK(a.owner.status) && a.route.method === "GET").slice(0, 3)
	if (!sample.length) return [result("CORS", "(app-wide)", "SKIPPED", "no route answered the owner, so there was nothing to ask")]
	for (const { url } of sample) {
		const response = await send("GET", url, { ...headers.owner("GET", url), Origin: PROBE_ORIGIN })
		const allowed = response.headers["access-control-allow-origin"]
		const credentials = response.headers["access-control-allow-credentials"] === "true"
		if (allowed === PROBE_ORIGIN && credentials)
			return [result("CORS", "(app-wide)", "CONFIRMED", `GET ${url} echoes any Origin with Allow-Credentials: true, so any website can read a signed-in user's data`, "CORS")]
		if (allowed === PROBE_ORIGIN || allowed === "*")
			return [result("CORS", "(app-wide)", "PUBLIC", `GET ${url} answers any origin (${allowed === "*" ? "*" : "echoed"}) but without credentials: fine for a public, token-only API`, "CORS")]
	}
	return [result("CORS", "(app-wide)", "PROTECTED", `a foreign Origin got no CORS approval on ${sample.length} route(s)`)]
}

// API8: the headers every answer should carry
function securityHeaders({ answers, baseUrl }) {
	const sample = answers.find(a => a.owner && OK(a.owner.status))
	if (!sample) return []
	const h = sample.owner.headers
	const gaps = []
	if (h["x-powered-by"]) gaps.push(`X-Powered-By names the framework (${h["x-powered-by"]})`)
	if (h["x-content-type-options"] !== "nosniff") gaps.push("no X-Content-Type-Options: nosniff")
	if (String(baseUrl).startsWith("https") && !h["strict-transport-security"]) gaps.push("no Strict-Transport-Security")
	return gaps.length
		? [result("SECURITY_HEADERS", "(app-wide)", "CONFIRMED", gaps.join("; "), "SECURITY_HEADERS")]
		: [result("SECURITY_HEADERS", "(app-wide)", "PROTECTED", "nosniff set and the framework is not named")]
}

// API3: secrets inside real answers. Only field names are reported, never their values.
// Besides the replayed routes, the owner reads up to 20 GET routes that take no id (/me, /settings)
async function dataExposure({ answers, routes, headers, send, prefix }) {
	const hits = []
	const replayed = new Set(answers.map(a => `${a.route.method} ${a.route.path}`))
	const extra = routes.filter(r => r.method === "GET" && !/[:{*<]/.test(r.path) && !replayed.has(`${r.method} ${r.path}`)).slice(0, 20)
	const reads = [...answers]
	for (const route of extra) {
		const url = prefix + route.path
		reads.push({ route, url, owner: await send("GET", url, headers.owner("GET", url)), other: null })
	}
	for (const { route, url, owner, other } of reads) {
		const tokenRoute = ISSUES_TOKENS.test(route.path)
		for (const response of [owner, other]) {
			if (!response || !OK(response.status)) continue
			const found = new Set()
			const visit = value => {
				if (Array.isArray(value)) value.forEach(visit)
				else if (value && typeof value === "object")
					for (const [key, v] of Object.entries(value)) {
						if (SECRET_FIELD.test(key) && !(tokenRoute && /token|otp/i.test(key)) && typeof v === "string" && v.length > 0) found.add(key)
						visit(v)
					}
			}
			visit(bodyOf(response))
			if (found.size) hits.push(`${route.method} ${url} (${[...found].join(", ")})`)
		}
	}
	const unique = [...new Set(hits)]
	return unique.length
		? [result("DATA_EXPOSURE", unique.length === 1 ? unique[0].split(" (")[0] : `${unique.length} routes`, "CONFIRMED", `secret fields in real answers: ${unique.slice(0, 5).join("; ")}${unique.length > 5 ? "; …" : ""}`, "DATA_EXPOSURE")]
		: []
}

// API8: what a malformed id makes the app say about itself
async function errorLeaks({ routes, prefix, headers, send }) {
	const targets = routes.filter(r => r.method === "GET" && /\/[:{]\w+\}?$/.test(r.path) && !/[*<]/.test(r.path)).slice(0, 8)
	for (const route of targets) {
		const url = prefix + route.path.replace(/[:{](\w+)\}?(\([^)]*\))?/g, () => encodeURIComponent(MALFORMED_ID))
		const response = await send("GET", url, headers.owner("GET", url))
		const match = response.text.match(STACK_TRACE)
		if (match)
			return [result("ERROR_LEAK", `GET ${route.path}`, "CONFIRMED", `a malformed id makes the answer show internals (${match[1] ?? "a stack trace"})`, "ERROR_LEAK")]
	}
	return targets.length ? [result("ERROR_LEAK", "(app-wide)", "PROTECTED", `malformed ids on ${targets.length} route(s) got no stack traces or driver errors`)] : []
}

// API2: does the API check the token's signature? A copy with alg none, and one with a changed claim
async function jwtForgery({ answers, headers, send }) {
	const target = answers.find(a => a.owner && OK(a.owner.status) && a.anonymous && [401, 403].includes(a.anonymous.status) && a.route.method === "GET")
	const parts = String(headers.owner.token ?? "").split(".")
	if (!target || parts.length !== 3) return []
	let header, payload
	try {
		header = JSON.parse(Buffer.from(parts[0], "base64url"))
		payload = JSON.parse(Buffer.from(parts[1], "base64url"))
	} catch {
		return []
	}
	const b64 = v => Buffer.from(JSON.stringify(v)).toString("base64url")
	const forgeries = [
		["alg: none", `${b64({ ...header, alg: "none" })}.${parts[1]}.`],
		["a changed claim, same signature", `${parts[0]}.${b64({ ...payload, rg_probe: 1 })}.${parts[2]}`]
	]
	for (const [kind, forged] of forgeries) {
		const response = await send("GET", target.url, headers.owner("GET", target.url, forged))
		if (OK(response.status))
			return [result("JWT", `GET ${target.route.path}`, "CONFIRMED", `a token with ${kind} was accepted, so anyone can mint their own`, "JWT")]
	}
	return [result("JWT", "(app-wide)", "PROTECTED", `tokens with alg none or a changed claim were refused on GET ${target.route.path}`)]
}

// API9: development routes the static scan flagged, asked without credentials
async function devRoutes({ routes, findings, fill, send }) {
	const flagged = findings.filter(f => f.rule === "NON_PROD_ROUTE" && f.route.startsWith("GET "))
	const out = []
	for (const f of flagged.slice(0, 10)) {
		const route = routes.find(r => `${r.method} ${r.path}` === f.route)
		if (!route) continue
		const { path, missing } = fill(route)
		if (missing.length) continue
		const response = await send("GET", path, {})
		out.push(OK(response.status)
			? result("NON_PROD_ROUTE", f.route, "CONFIRMED", "the development route answers anyone in this environment", "NON_PROD_ROUTE")
			: result("NON_PROD_ROUTE", f.route, "PROTECTED", `answered ${response.status} without credentials`, "NON_PROD_ROUTE"))
	}
	return out
}

// API4 (opt-in): about 20 wrong logins for an account that does not exist, so no real account locks
async function rateLimits({ routes, findings, fill, send, probes }) {
	const attempts = probes.attempts ?? 20
	const flagged = new Set(findings.filter(f => f.rule === "RATE_LIMIT").map(f => f.route))
	const targets = routes.filter(r => flagged.has(`${r.method} ${r.path}`)).slice(0, 5)
	const out = []
	for (const route of targets) {
		const { path, missing } = fill(route)
		if (missing.length) continue
		let limited = null
		let last = null
		for (let i = 0; i < attempts && !limited; i++) {
			const body = { email: "routeguard-probe@invalid.test", username: "routeguard-probe", password: `not-the-password-${i}`, otp: "000000", code: "000000" }
			const response = await send("POST", path, {}, body)
			last = response.status
			if (response.status === 429 || response.status === 423 || response.headers["retry-after"]) limited = { i: i + 1, status: response.status }
		}
		out.push(limited
			? result("RATE_LIMIT", `POST ${route.path}`, "PROTECTED", `limited after ${limited.i} attempts (${limited.status})`, "RATE_LIMIT")
			: [0, 404, 405].includes(last) || last >= 500
				? result("RATE_LIMIT", `POST ${route.path}`, "INCONCLUSIVE", `the route answered ${last || "nothing"}, so the attempts never reached a check`, "RATE_LIMIT")
				: result("RATE_LIMIT", `POST ${route.path}`, "CONFIRMED", `${attempts} wrong attempts in a row and none was limited (each answered ${last})`, "RATE_LIMIT"))
	}
	return out
}

// API7 (opt-in): a local listener's URL goes into the field the static scan named; a hit is proof
async function ssrf({ routes, findings, fill, headers, send, probes }) {
	const flagged = findings.filter(f => f.rule === "SSRF" && f.severity === "HIGH" && f.input)
	if (!flagged.length) return []
	const hits = new Set()
	const listener = http.createServer((req, res) => {
		hits.add(req.url.split("?")[0].slice(1))
		res.end("routeguard")
	})
	await new Promise(resolve => listener.listen(0, "0.0.0.0", resolve))
	const host = probes.canaryHost ?? "127.0.0.1"
	const out = []
	try {
		for (const f of flagged.slice(0, 5)) {
			const [method, routePath] = f.route.split(" ")
			const route = routes.find(r => r.method === method && r.path === routePath)
			if (!route) continue
			const { path, missing } = fill(route)
			if (missing.length) {
				out.push(result("SSRF", f.route, "SKIPPED", `no value for :${missing.join(", :")}`, "SSRF"))
				continue
			}
			const mark = randomUUID()
			const canary = `http://${host}:${listener.address().port}/${mark}`
			const url = f.input.in === "query" ? `${path}${path.includes("?") ? "&" : "?"}${f.input.name}=${encodeURIComponent(canary)}` : path
			// a body goes as JSON first, then as a form, since handlers often read only one of them
			const bodies = f.input.in === "body" ? [{ [f.input.name]: canary }, new URLSearchParams({ [f.input.name]: canary })] : [undefined]
			for (const body of bodies) {
				if (hits.has(mark)) break
				await send(method, url, headers.owner(method, url), body)
				for (let waited = 0; waited < 3000 && !hits.has(mark); waited += 100) await new Promise(r => setTimeout(r, 100))
			}
			out.push(hits.has(mark)
				? result("SSRF", f.route, "CONFIRMED", `the server fetched a URL taken from ${f.input.in}.${f.input.name}`, "SSRF")
				: result("SSRF", f.route, "INCONCLUSIVE", `no request reached ${host}; the app may not be able to reach this machine (set canaryHost)`, "SSRF"))
		}
	} finally {
		listener.close()
	}
	return out
}

export async function runProbes(context) {
	const { probes } = context
	const all = [
		...(await cors(context)),
		...securityHeaders(context),
		...(await dataExposure(context)),
		...(await errorLeaks(context)),
		...(await jwtForgery(context)),
		...(await devRoutes(context))
	]
	if (probes.rateLimits) all.push(...(await rateLimits(context)))
	if (probes.ssrf) all.push(...(await ssrf(context)))
	return all
}
