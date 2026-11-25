import { walk } from "../mapper.js"

// Mongoose, Sequelize, Prisma and raw query calls that load or change a record
export const DB_CALL =
	/^(find|findOne|findById|findByPk|findUnique|findFirst|findByIdAnd(Update|Delete|Remove)|findOneAnd(Update|Delete|Remove|Replace)|update|updateOne|updateMany|delete|deleteOne|deleteMany|destroy|remove|replaceOne|query|execute)$/

export const DB_WRITE =
	/^(save|create|insert|insertOne|insertMany|upsert|bulkCreate|update|updateOne|updateMany|findByIdAnd(Update|Delete|Remove)|findOneAnd(Update|Delete|Remove|Replace)|delete|deleteOne|deleteMany|destroy|remove|replaceOne)$/

// where the signed-in caller's identity usually lives
const IDENTITY_KEYS = new Set(["user", "auth", "session", "userId", "currentUser"])

export const isMember = (node, objectName, propertyName) =>
	node?.type === "MemberExpression" &&
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
		if (node.type !== "CallExpression" || node.callee.type !== "MemberExpression") return
		const method = node.callee.property.name
		if (pattern.test(method)) calls.push({ node, method, line: node.loc.start.line })
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
