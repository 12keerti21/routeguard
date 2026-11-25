import { walk, isCallNode } from "../mapper.js"
import { calleeName } from "./handler.js"

// endpoints worth brute-forcing, judged on the last path segment: /auth/login, /forgot-password, /otp
const GUESSABLE = new Set(["login", "signin", "otp", "2fa", "mfa", "totp", "verify", "forgot", "reset", "password", "register", "signup", "auth"])
// "flushProjectToTpds" has "otp" in it, "loginLimit" has "login": split into words first
const words = segment =>
	segment
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.split(/[\s_.-]+/)
		.map(w => w.toLowerCase())
		.flatMap((w, i, all) => (all[i + 1] && ["log", "sign"].includes(w) && ["in", "up"].includes(all[i + 1]) ? [w + all[i + 1]] : [w]))
const CODE_CHECK = { test: segment => words(segment).some(w => ["otp", "2fa", "mfa", "totp", "verify", "code"].includes(w)) }
const LIMITER = /limit|throttle|slow.?down|brute|pace|lockout/i
// throttling done in code: signInPace.check(...), recordFailedAttempt(user)
const LIMITER_CALL = /rate.?limit|throttle|pace|lockout|attempts?|brute|penalt|cooldown/i
const DEPTH = 2

function throttlesInCode(route, fn, file, depth = 0, seen = new Set()) {
	if (!fn || depth > DEPTH || seen.has(fn)) return false
	seen.add(fn)
	let found = false
	walk(fn.body, n => {
		if (found || !isCallNode(n)) return
		if (LIMITER_CALL.test(calleeName(n))) found = true
		else {
			const target = route.resolve?.(file, n.callee)
			if (target && throttlesInCode(route, target.fn, target.file, depth + 1, seen)) found = true
		}
	})
	return found
}

// API4 and API2: a credential or code can be guessed as fast as the client can send requests
export function rateLimit(route) {
	if (route.method !== "POST") return null
	const segment = route.path.split("/").filter(s => s && !/^[:{]/.test(s)).at(-1) ?? ""
	if (!words(segment).some(w => GUESSABLE.has(w))) return null
	// a signed-in caller setting a password is not guessing one; a code check behind a session still is
	if (route.auth && !CODE_CHECK.test(segment)) return null
	if (route.middleware.some(m => LIMITER.test(m))) return null
	if (throttlesInCode(route, route.fn, route.fnPath)) return null

	return {
		rule: "RATE_LIMIT",
		owasp: "API4:2023 Unrestricted Resource Consumption / API2:2023 Broken Authentication",
		severity: "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: `${route.file}:${route.line}`,
		message: `"${segment}" takes a password or code, and neither its middleware nor its handler limits how often it can be tried.`,
		fix: "Add a limiter keyed on the caller and the account, e.g. express-rate-limit: router.post(path, rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }), handler)."
	}
}
