import { walk, isCallNode } from "../mapper.js"
import { calleeName } from "./handler.js"

// endpoints worth brute-forcing, judged on the last path segment: /auth/login, /forgot-password, /otp
const GUESSABLE = /login|log-in|signin|sign-in|otp|2fa|mfa|(^|[-_])verify([-_]|$)|forgot|reset|password|register|signup|sign-up|^auth$/i
const CODE_CHECK = /otp|2fa|mfa|(^|[-_])verify([-_]|$)|code/i
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
	if (!GUESSABLE.test(segment)) return null
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
