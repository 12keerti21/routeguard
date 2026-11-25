import { walk, isMemberNode, isCallNode } from "../mapper.js"

// Mongoose, Sequelize, Prisma and raw query calls that load or change a record
export const DB_CALL =
	/^(find|findOne|findById|findByPk|findUnique|findFirst|findByIdAnd(Update|Delete|Remove)|findOneAnd(Update|Delete|Remove|Replace)|update|updateOne|updateMany|delete|deleteOne|deleteMany|destroy|remove|replaceOne|query|execute)$/

// service calls such as userService.getUserById(id) or updateArticle(slug, body)
export const RECORD_ACCESS = new RegExp(
	`${DB_CALL.source}|^(get|find|fetch|load|read|update|edit|patch|delete|remove|destroy|archive)[A-Z_]`
)

export const DB_WRITE =
	/^(save|create|insert|insertOne|insertMany|upsert|bulkCreate|update|updateOne|updateMany|findByIdAnd(Update|Delete|Remove)|findOneAnd(Update|Delete|Remove|Replace)|delete|deleteOne|deleteMany|destroy|remove|replaceOne)$/

// where the signed-in caller's identity usually lives
const IDENTITY_KEYS = new Set(["user", "auth", "session", "userId", "currentUser"])

export const isMember = (node, objectName, propertyName) =>
	isMemberNode(node) &&
	node.object.type === "Identifier" &&
	node.object.name === objectName &&
	(propertyName === undefined || node.property.name === propertyName)

// the names the handler gives req and res: (request, response) => {} works too
export function handlerParams(fn) {
	const [reqParam, resParam] = fn.params
	return {
		req: reqParam?.type === "Identifier" ? reqParam.name : "req",
		res: resParam?.type === "Identifier" ? resParam.name : "res"
	}
}

export function dbCalls(fn, pattern) {
	const calls = []
	walk(fn.body, node => {
		if (!isCallNode(node)) return
		const method = isMemberNode(node.callee) ? node.callee.property.name : node.callee.name
		if (method && pattern.test(method)) calls.push({ node, method, line: node.loc.start.line })
	})
	return calls
}

export function readsIdentity(fn) {
	const { req, res } = handlerParams(fn)
	let found = false
	walk(fn.body, n => {
		if (isMember(n, req) && IDENTITY_KEYS.has(n.property.name)) found = true
		if (isMember(n, res, "locals")) found = true
	})
	return found
}

// findings point at the line in the handler, which may live in a controller file
export const whereOf = (route, line) => `${route.fnFile ?? route.file}:${line}`
