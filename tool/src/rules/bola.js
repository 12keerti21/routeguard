import { walk } from "../mapper.js"
import { DB_CALL, dbCalls, handlerParams, isMember, readsIdentity } from "./handler.js"

// names that carry a value from req.params: const id = req.params.id, const { id } = req.params
function paramDerivedNames(fn, req) {
	const names = new Set()
	walk(fn.body, node => {
		if (node.type !== "VariableDeclarator" || !node.init) return
		const fromParams =
			isMember(node.init, req, "params") ||
			(node.init.type === "MemberExpression" && isMember(node.init.object, req, "params"))
		if (!fromParams) return
		if (node.id.type === "Identifier") names.add(node.id.name)
		if (node.id.type === "ObjectPattern")
			node.id.properties.forEach(p => p.value?.type === "Identifier" && names.add(p.value.name))
	})
	return names
}

function usesParam(node, req, derived) {
	let found = false
	walk(node, n => {
		if (n.type === "MemberExpression" && isMember(n.object, req, "params")) found = true
		if (n.type === "Identifier" && derived.has(n.name)) found = true
	})
	return found
}

// API1: a record is fetched or changed by a client-supplied id, and the handler never
// compares it with the caller, so any signed-in user can reach anyone's record
export function bola(route) {
	if (!/[:{]/.test(route.path) || route.role || !route.fn) return null
	// an unauthenticated read is usually a public catalogue on purpose (books, products)
	if (!route.auth && route.method === "GET") return null

	const { req } = handlerParams(route.fn)
	const derived = paramDerivedNames(route.fn, req)
	const calls = dbCalls(route.fn, DB_CALL).filter(c => c.node.arguments.some(a => usesParam(a, req, derived)))
	if (calls.length === 0 || readsIdentity(route.fn)) return null

	const write = ["PUT", "PATCH", "DELETE"].includes(route.method)
	return {
		rule: "BOLA",
		owasp: !route.auth
			? "API1/API2: no auth at all"
			: write
				? "API1:2023 BOLA, or API5:2023 BFLA if this is a shared record only admins should change"
				: "API1:2023 Broken Object Level Authorization",
		severity: !route.auth || write ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: `${route.file}:${calls[0].line}`,
		message: `${calls.map(c => c.method).join(", ")} uses an id from the URL, and the handler never checks it against the caller (req.user).`,
		fix: "If the record has an owner, scope the query to the caller: findOne({ _id: id, owner: req.user._id }). If it is shared, add a role check such as [auth, admin]."
	}
}
