import { DB_CALL, DB_WRITE, checksBodyCredential, dbCalls, hasRole, readsIdentity, whereOf } from "./handler.js"

// res.sendFile(adminIndex): the admin page itself is public, its actions need the check
const PAGE_ONLY = /^(sendFile|render|redirect|download|readFile|createReadStream)$/

// path segments that name operator-only functions
const SENSITIVE = /(^|\/)(admin|internal|manage|system|config|debug|metrics|logs?|keys?|secrets?|backup)(\/|$)/i

// an API key or basic auth is usually issued to operators only; a user login is not
function sensitiveSeverity(route) {
	if (route.middleware.some(m => /api.?(key|auth)|basic/i.test(m))) return "LOW"
	if (route.fn && dbCalls(route.fn, DB_CALL).length === 0 && dbCalls(route.fn, PAGE_ONLY).length > 0) return "LOW"
	return "HIGH"
}

// API5: a function meant for privileged users is reachable by anyone signed in, or by anyone
export function bfla(route) {
	if (hasRole(route)) return null

	const sensitive = route.path.match(SENSITIVE)
	if (sensitive) {
		return {
			rule: "BFLA",
			owasp: "API5:2023 Broken Function Level Authorization",
			severity: sensitiveSeverity(route),
			route: `${route.method} ${route.path}`,
			where: `${route.file}:${route.line}`,
			message: `"${sensitive[2]}" names an operator function, but the route has ${route.auth ? "no role check" : "no auth or role check"}.`,
			fix: "Add a role check, e.g. router.get(path, [auth, admin], handler), or remove the route from production."
		}
	}

	// a signed-in user creates a record that is not tied to them, so it is shared data,
	// and changing shared data is usually an admin's job (catalogue items, settings)
	// routes with an id in the path are covered by the BOLA rule
	if (!route.auth || route.method === "GET" || /[:{]/.test(route.path) || !route.fn) return null
	const writes = dbCalls(route.fn, DB_WRITE)
	if (writes.length === 0 || readsIdentity(route.fn) || checksBodyCredential(route.fn)) return null

	return {
		rule: "BFLA",
		owasp: "API5:2023 Broken Function Level Authorization",
		severity: "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: whereOf(route, writes[0].line),
		message: `Any signed-in user can ${writes.map(w => w.method).join(", ")} here, and the new record is not tied to them, so this looks like shared data with no role check.`,
		fix: "Add a role check such as [auth, admin], or store the caller as owner (owner: req.user._id) if users should own these records."
	}
}
