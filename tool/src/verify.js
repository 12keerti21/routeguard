// Runtime check: replay routes against a running app as two real users and compare the answers.
// Static analysis says where a check looks missing; this says whether another user really gets in.

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

// a user is fixed headers, or a login call whose answer holds the token
async function signIn(baseUrl, user, timeoutMs) {
	if (!user) return null
	if (user.headers) return user.headers
	const { login } = user
	const res = await call(baseUrl, login.method ?? "POST", login.path, {}, login.body, timeoutMs)
	if (!OK(res.status)) throw new Error(`login ${login.path} answered ${res.status}`)
	const token = pick(JSON.parse(res.text), login.token)
	if (!token) throw new Error(`login ${login.path}: no value at "${login.token}"`)
	return { [login.header ?? "Authorization"]: `${login.prefix ?? "Bearer "}${token}` }
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
export async function verify({ routes, findings, baseUrl, config, allowWrites = false, timeoutMs = 10000 }) {
	const settings = expand(config)
	const prefix = settings.pathPrefix ?? ""
	const headers = {
		owner: await signIn(baseUrl, settings.users?.owner, timeoutMs),
		other: await signIn(baseUrl, settings.users?.other, timeoutMs)
	}
	if (!headers.owner || !headers.other) throw new Error("the config needs users.owner and users.other")

	const results = []
	for (const { route, staticRule } of candidates(routes, findings, allowWrites)) {
		const { path, missing } = fillPath(route, settings.params ?? {}, settings.routes ?? {})
		const key = `${route.method} ${route.path}`
		if (missing.length) {
			results.push({ route: key, staticRule, verdict: "SKIPPED", reason: `no value for :${missing.join(", :")}` })
			continue
		}
		const body = settings.bodies?.[key]
		const url = prefix + path
		// the owner goes last for writes, so a delete by the other user is not hidden by the owner's own
		const owner = WRITE.has(route.method) ? null : await call(baseUrl, route.method, url, headers.owner, body, timeoutMs)
		const other = await call(baseUrl, route.method, url, headers.other, body, timeoutMs)
		const anonymous = await call(baseUrl, route.method, url, {}, body, timeoutMs)
		results.push({ route: key, path: url, staticRule, ...judge(route, staticRule, owner, other, anonymous), status: { owner: owner?.status, other: other.status, anonymous: anonymous.status } })
	}
	return results
}

// CONFIRMED: someone got in who should not · PUBLIC: open to anyone, and the code never asks for a login,
// so it is probably meant to be public · PROTECTED: the second user was refused or got their own data
function judge(route, staticRule, owner, other, anonymous) {
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
	if (owner && OK(other.status) && takesId && sameObject(owner, other))
		return { verdict: "CONFIRMED", reason: "another user got the owner's data" }
	if (!owner && OK(other.status)) return { verdict: "CONFIRMED", reason: "another user's write was accepted" }
	if (!takesId && OK(other.status) && staticRule) return { verdict: "CONFIRMED", reason: "an ordinary user reaches this operator route" }
	if (owner && OK(other.status)) return { verdict: "PROTECTED", reason: "another user got different data (likely their own)" }
	// the owner got in and the other user got any 4xx: some apps refuse with 400 rather than 403
	if (DENIED(other.status) || (owner && OK(owner.status) && other.status >= 400 && other.status < 500))
		return { verdict: "PROTECTED", reason: `another user was refused (${other.status})` }
	return { verdict: "INCONCLUSIVE", reason: `another user got ${other.status}` }
}
