import { walk, isCallNode } from "../mapper.js"
import { calleeName, hasRole } from "./handler.js"

// flows a bot profits from automating: buying out stock, farming referrals, mass reviews
// matched against whole path segments: "books" is a catalogue and "tokenTransfer" a session hand-off
const MONEY = /^(checkout|orders?|purchases?|buy|redeem|coupons?|vouchers?|promos?|promo-?codes?|referrals?|refer|withdraw\w*|payouts?|gift-?cards?|credits?|rewards?)$/i
const ABUSE = /^(book|bookings?|reserv\w*|seats?|tickets?|votes?|likes?|reviews?|comments?|invites?|invitations?)$/i
// anti-automation: a limiter, a captcha, a proof of work, a queue
// robots(…) serves robots.txt; bot only counts as botProtection, botGuard, botDetect
const GUARD = /limit|throttle|slow.?down|captcha|turnstile|bot.?(guard|protect|check|detect)|antiAutomation|proof.?of.?work|queue/i
const DEPTH = 2

function guardedInCode(route, fn, file, depth = 0, seen = new Set()) {
	if (!fn || depth > DEPTH || seen.has(fn)) return false
	seen.add(fn)
	let found = false
	walk(fn.body, n => {
		if (found || !isCallNode(n)) return
		if (GUARD.test(calleeName(n))) found = true
		else {
			const target = route.resolve?.(file, n.callee)
			if (target && guardedInCode(route, target.fn, target.file, depth + 1, seen)) found = true
		}
	})
	return found
}

// API6: a business flow can be run by a script as fast as it likes
export function businessFlow(route) {
	if (!["POST", "PUT", "PATCH"].includes(route.method)) return null
	const segments = route.path.split("/").filter(s => s && !/^[:{]/.test(s))
	// a transfer is money only next to money words: /wallet/transfer, not /labels/transfer
	const moneyTransfer = segments.some(s => /^transfers?$/i.test(s)) && segments.some(s => /wallet|fund|balance|payment|account|money|credit/i.test(s))
	const segment = (moneyTransfer && "transfer") || segments.find(s => MONEY.test(s)) || segments.find(s => ABUSE.test(s))
	if (!segment || hasRole(route)) return null
	// /invites/:token/accept: the token gates it, one use per token
	if (/[:{]\w*(token|code|secret|hash)/i.test(route.path)) return null
	if (route.middleware.some(m => GUARD.test(m)) || guardedInCode(route, route.fn, route.fnPath)) return null

	const money = MONEY.test(segment)
	return {
		rule: "BUSINESS_FLOW",
		owasp: "API6:2023 Unrestricted Access to Sensitive Business Flows",
		severity: money ? "MEDIUM" : "LOW",
		route: `${route.method} ${route.path}`,
		where: `${route.file}:${route.line}`,
		message: `"${segment}" is a ${money ? "money or stock" : "reputation or capacity"} flow with no limiter, captcha or other anti-automation, so a script can ${money ? "buy out, redeem or transfer at scale" : "flood it"}.`,
		fix: "Limit per account and per device (express-rate-limit keyed on the user), add a captcha or a queue for the flow, and alert on bursts."
	}
}
