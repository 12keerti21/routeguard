// Runtime check: replay routes against a running app as two real users and compare the answers.
// Static analysis says where a check looks missing; this says whether another user really gets in.
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto"
import readline from "node:readline/promises"
import { discoverParams } from "./discover.js"

const WRITE = new Set(["PUT", "PATCH", "DELETE", "POST"])
const OK = status => status >= 200 && status < 300
const DENIED = status => [401, 403, 404].includes(status)

// "${JUICE_PASSWORD}" in the config reads the environment, so passwords stay out of the file
function expand(value) {
	if (typeof value === "string") return value.replace(/\$\{(\w+)\}/g, (_, name) => process.env[name] ?? "")
	if (Array.isArray(value)) return value.map(expand)
	if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expand(v)]))
	return value
}

const pick = (object, dotted) => dotted.split(".").reduce((o, k) => o?.[k], object)

async function call(baseUrl, method, path, headers = {}, body, timeoutMs) {
	const controller = new AbortController()
	const timer = setTimeout(() => controller.abort(), timeoutMs)
	try {
		const res = await fetch(new URL(path, baseUrl), {
			method,
			headers: { accept: "application/json", ...(body ? { "content-type": "application/json" } : {}), ...headers },
			body: body ? JSON.stringify(body) : undefined,
			redirect: "manual",
			signal: controller.signal
		})
		return { status: res.status, text: await res.text() }
	} catch (error) {
		return { status: 0, text: "", error: error.name === "AbortError" ? "timeout" : error.message }
	} finally {
		clearTimeout(timer)
	}
}

// DPoP (RFC 9449): each user gets its own P-256 key, and every request carries a fresh proof
// signed with it, so apps that bind tokens to a key can be tested too
const base64url = value => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url")

function dpopKey() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
	const { kty, crv, x, y } = publicKey.export({ format: "jwk" })
	return { privateKey, jwk: { kty, crv, x, y } }
}

export function dpopProof(key, method, htu, accessToken) {
	const header = base64url({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk })
	const payload = base64url({
		htm: method,
		htu,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...(accessToken ? { ath: createHash("sha256").update(accessToken).digest("base64url") } : {})
	})
	const signature = sign("sha256", Buffer.from(`${header}.${payload}`), { key: key.privateKey, dsaEncoding: "ieee-p1363" })
	return `${header}.${payload}.${signature.toString("base64url")}`
}

// "{{login_token}}" is a value saved by an earlier login step; "{{prompt:OTP for alice}}" asks in the terminal
async function fillTemplate(value, saved, ask) {
	if (typeof value === "string") {
		let out = value
		for (const [match, inner] of value.matchAll(/\{\{\s*([^}]+?)\s*\}\}/g)) {
			const filled = inner.startsWith("prompt:") ? await ask(inner.slice(7).trim()) : saved[inner]
			if (filled === undefined) throw new Error(`no saved value "${inner}" for the login`)
			out = out.replace(match, filled)
		}
		return out
	}
	if (Array.isArray(value)) return Promise.all(value.map(v => fillTemplate(v, saved, ask)))
	if (value && typeof value === "object") {
		const entries = []
		for (const [k, v] of Object.entries(value)) entries.push([k, await fillTemplate(v, saved, ask)])
		return Object.fromEntries(entries)
	}
	return value
}

async function askInTerminal(label) {
	// a terminal, or a pipe that feeds one answer per line (for runs driven from another program)
	const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: Boolean(process.stdin.isTTY) })
	try {
		return (await rl.question(`${label}: `)).trim()
	} finally {
		rl.close()
	}
}

// a user is fixed headers, or login steps whose last answer holds the token; returns the headers
// for each request (a DPoP user signs a new proof every time)
async function signIn(baseUrl, user, settings, timeoutMs, ask = askInTerminal) {
	if (!user) return null
	if (user.headers) return () => user.headers
	const key = user.dpop ? dpopKey() : null
	const origin = String(settings.dpopOrigin ?? baseUrl).replace(/\/+$/, "")
	const htu = path => `${origin}${path.split("?")[0]}`
	const steps = Array.isArray(user.login) ? user.login : [user.login]
	const saved = {}
	let token = null
	for (const step of steps) {
		const method = step.method ?? "POST"
		const body = await fillTemplate(step.body, saved, ask)
		const res = await call(baseUrl, method, step.path, key ? { DPoP: dpopProof(key, method, htu(step.path)) } : {}, body, timeoutMs)
		if (!OK(res.status)) throw new Error(`login step ${step.path} answered ${res.status}: ${res.text.slice(0, 160)}`)
		const answer = JSON.parse(res.text || "{}")
		// a wrong path names what the answer does hold, so the config is quick to fix
		const take = dotted => {
			const value = pick(answer, dotted)
			if (value === undefined) throw new Error(`login step ${step.path}: no "${dotted}" in the answer (it has: ${Object.keys(answer).join(", ")})`)
			return value
		}
		for (const [name, dotted] of Object.entries(step.save ?? {})) saved[name] = take(dotted)
		if (step.token) token = take(step.token)
	}
	if (!token) throw new Error(`login: no step returned a token (set "token" on the last step)`)
	const last = steps.at(-1)
	const scheme = user.scheme ?? last.prefix?.trim() ?? (key ? "DPoP" : "Bearer")
	const header = last.header ?? "Authorization"
	return (method, path) => ({ [header]: `${scheme} ${token}`, ...(key ? { DPoP: dpopProof(key, method, htu(path), token) } : {}) })
}

// the same object, by content: ignore key order and timestamps that change between calls
function sameObject(a, b) {
	if (a.text === b.text) return true
	try {
		const strip = value =>
			JSON.stringify(value, (key, v) => (/^(updatedAt|createdAt|timestamp|time|date|requestId|csrf\w*)$/i.test(key) ? undefined : v))
		return strip(JSON.parse(a.text)) === strip(JSON.parse(b.text))
	} catch {
		return false
	}
}

// an answer with nothing in it beyond the ids the request itself sent: { userId, courses: [] }.
// Two such answers being equal proves nothing about access
function carriesData(response, path) {
	let body
	try {
		body = JSON.parse(response.text)
	} catch {
		return response.text.trim().length > 0
	}
	const echoed = new Set(path.split("/").map(decodeURIComponent))
	const leaves = []
	const visit = value => {
		if (Array.isArray(value)) value.forEach(visit)
		else if (value && typeof value === "object") Object.values(value).forEach(visit)
		else if (value !== null && value !== "" && typeof value !== "boolean" && !echoed.has(String(value))) leaves.push(value)
	}
	visit(body)
	return leaves.length > 0
}

function fillPath(route, params, overrides) {
	const own = overrides[`${route.method} ${route.path}`] ?? overrides[route.path] ?? {}
	const missing = []
	const path = route.path.replace(/[:{](\w+)\}?(\([^)]*\))?/g, (_, name) => {
		const value = own[name] ?? params[name]
		if (value === undefined) missing.push(name)
		return encodeURIComponent(value ?? "")
	})
	return { path, missing }
}

// which routes to replay: every route that takes an id (BOLA) and every route a static finding
// called operator-only (BFLA), reads always, writes only when asked
function candidates(routes, findings, allowWrites) {
	const flagged = new Map(findings.map(f => [f.route, f.rule]))
	const seen = new Set()
	return routes.filter(r => {
		const key = `${r.method} ${r.path}`
		if (seen.has(key) || /[*<]/.test(r.path) || r.method === "ALL" || r.method === "OPTIONS" || r.method === "HEAD") return false
		if (WRITE.has(r.method) && !allowWrites) return false
		const takesId = /[:{]/.test(r.path)
		const operator = ["BFLA"].includes(flagged.get(key))
		if (!takesId && !operator) return false
		seen.add(key)
		return true
	}).map(r => ({ route: r, staticRule: flagged.get(`${r.method} ${r.path}`) ?? null }))
}

// owner: the user who owns the ids in the config · other: a second ordinary user · anonymous: no credentials
export async function verify({ routes, findings, baseUrl, config, allowWrites = false, timeoutMs = 10000, ask }) {
	const settings = expand(config)
	const prefix = settings.pathPrefix ?? ""
	const headers = {
		owner: await signIn(baseUrl, settings.users?.owner, settings, timeoutMs, ask),
		other: await signIn(baseUrl, settings.users?.other, settings, timeoutMs, ask)
	}
	if (!headers.owner || !headers.other) throw new Error("the config needs users.owner and users.other")

	// ids the config leaves out are looked up from the app's own list routes, unless "discover": false
	const params = settings.params ?? {}
	let discovered = []
	let perRoute = new Map()
	if (settings.discover !== false) {
		const fetchAs = (who, url) => call(baseUrl, "GET", prefix + url, headers[who]("GET", prefix + url), undefined, timeoutMs)
		;({ perRoute, notes: discovered } = await discoverParams({ routes, known: params, fetchAs }))
	}

	const results = []
	for (const { route, staticRule } of candidates(routes, findings, allowWrites)) {
		const found = perRoute.get(route.path) ?? { values: {}, sources: {} }
		const { path, missing } = fillPath(route, { ...found.values, ...params }, settings.routes ?? {})
		const key = `${route.method} ${route.path}`
		if (missing.length) {
			results.push({ route: key, staticRule, verdict: "SKIPPED", reason: `no value for :${missing.join(", :")}` })
			continue
		}
		const body = settings.bodies?.[key]
		const url = prefix + path
		// the owner goes last for writes, so a delete by the other user is not hidden by the owner's own
		const owner = WRITE.has(route.method) ? null : await call(baseUrl, route.method, url, headers.owner(route.method, url), body, timeoutMs)
		const other = await call(baseUrl, route.method, url, headers.other(route.method, url), body, timeoutMs)
		const anonymous = await call(baseUrl, route.method, url, {}, body, timeoutMs)
		let verdict = judge(route, staticRule, owner, other, anonymous, url)
		// an id the other user can also list may be theirs to read, so reading it proves nothing
		const shared = Object.values(found.sources).filter(d => !d.ownerOnly)
		if (verdict.verdict === "CONFIRMED" && /owner's data/.test(verdict.reason) && shared.length)
			verdict = { verdict: "INCONCLUSIVE", reason: `the other user can also list :${shared.map(d => d.param).join(", :")}, so reading it may be allowed; give an id only the owner has` }
		results.push({ route: key, path: url, staticRule, ...verdict, status: { owner: owner?.status, other: other.status, anonymous: anonymous.status } })
	}
	Object.defineProperty(results, "discovered", { value: discovered })
	return results
}

// CONFIRMED: someone got in who should not · PUBLIC: open to anyone, and the code never asks for a login,
// so it is probably meant to be public · PROTECTED: the second user was refused or got their own data
function judge(route, staticRule, owner, other, anonymous, path) {
	if (other.error) return { verdict: "INCONCLUSIVE", reason: `request failed: ${other.error}` }
	const takesId = /[:{]/.test(route.path)

	if (OK(anonymous.status) && (!takesId || (owner && OK(owner.status) && sameObject(owner, anonymous)))) {
		if (route.auth) return { verdict: "CONFIRMED", reason: "the code expects a login, but it answers without any credentials" }
		if (staticRule) return { verdict: "CONFIRMED", reason: "anyone can reach it, with no credentials" }
		return { verdict: "PUBLIC", reason: "open to anyone and the code asks for no login; confirm it is meant to be public" }
	}
	if (owner && !OK(owner.status)) return { verdict: "INCONCLUSIVE", reason: `the owner got ${owner.status}: check the ids and paths in the config` }
	// readable with no credentials and the code asks for none, even if the answer varies per viewer
	if (OK(anonymous.status) && !route.auth && !staticRule)
		return { verdict: "PUBLIC", reason: "open to anyone and the code asks for no login; confirm it is meant to be public" }
	if (owner && OK(other.status) && takesId && sameObject(owner, other)) {
		if (!carriesData(owner, path))
			return { verdict: "INCONCLUSIVE", reason: "both users got the same empty answer; give the owner's record some data to compare" }
		return { verdict: "CONFIRMED", reason: "another user got the owner's data" }
	}
	if (!owner && OK(other.status)) return { verdict: "CONFIRMED", reason: "another user's write was accepted" }
	if (!takesId && OK(other.status) && staticRule) return { verdict: "CONFIRMED", reason: "an ordinary user reaches this operator route" }
	if (owner && OK(other.status)) return { verdict: "PROTECTED", reason: "another user got different data (likely their own)" }
	// the owner got in and the other user got any 4xx: some apps refuse with 400 rather than 403
	if (DENIED(other.status) || (owner && OK(owner.status) && other.status >= 400 && other.status < 500))
		return { verdict: "PROTECTED", reason: `another user was refused (${other.status})` }
	return { verdict: "INCONCLUSIVE", reason: `another user got ${other.status}` }
}
