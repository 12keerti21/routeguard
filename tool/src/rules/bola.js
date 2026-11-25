import { walk } from "../mapper.js"

// Mongoose, Sequelize, Prisma and raw query calls that load or change a record
const DB_CALL =
	/^(find|findOne|findById|findByPk|findUnique|findFirst|findByIdAnd(Update|Delete|Remove)|findOneAnd(Update|Delete|Remove|Replace)|update|updateOne|updateMany|delete|deleteOne|deleteMany|destroy|remove|replaceOne|query|execute)$/

// where the signed-in caller's identity usually lives
const IDENTITY_KEYS = new Set(["user", "auth", "session", "userId", "currentUser"])

const isMember = (node, objectName, propertyName) =>
	node?.type === "MemberExpression" &&
	node.object.type === "Identifier" &&
	node.object.name === objectName &&
	(propertyName === undefined || node.property.name === propertyName)

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

function readsIdentity(fn, req, res) {
	let found = false
	walk(fn.body, n => {
		if (isMember(n, req) && IDENTITY_KEYS.has(n.property.name)) found = true
		if (isMember(n, res, "locals")) found = true
	})
	return found
}

// API1: a record is fetched or changed by a client-supplied id, and the handler never
// compares it with the caller, so any signed-in user can reach anyone's record
export function bola(route) {
	if (!/[:{]/.test(route.path) || route.role || !route.fn) return null
	// an unauthenticated read is usually a public catalogue on purpose (books, products)
	if (!route.auth && route.method === "GET") return null

	const [reqParam, resParam] = route.fn.params
	const req = reqParam?.type === "Identifier" ? reqParam.name : "req"
	const res = resParam?.type === "Identifier" ? resParam.name : "res"
	const derived = paramDerivedNames(route.fn, req)

	const calls = []
	walk(route.fn.body, node => {
		if (node.type !== "CallExpression" || node.callee.type !== "MemberExpression") return
		const method = node.callee.property.name
		if (DB_CALL.test(method) && node.arguments.some(a => usesParam(a, req, derived)))
			calls.push({ method, line: node.loc.start.line })
	})
	if (calls.length === 0 || readsIdentity(route.fn, req, res)) return null

	const write = ["PUT", "PATCH", "DELETE"].includes(route.method)
	return {
		rule: "BOLA",
		owasp: route.auth ? "API1:2023 Broken Object Level Authorization" : "API1/API2: no auth at all",
		severity: !route.auth || write ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: `${route.file}:${calls[0].line}`,
		message: `${calls.map(c => c.method).join(", ")} uses an id from the URL, and the handler never checks it against the caller (req.user).`,
		fix: "Scope the query to the caller, e.g. findOne({ _id: id, owner: req.user._id }), or check ownership before acting."
	}
}
