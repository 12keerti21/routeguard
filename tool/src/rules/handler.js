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

// helpers that turn the request into the caller: authenticatedUsers.from(req), jwtFrom(req), getUser(req)
const IDENTITY_FN = /user|auth|jwt|token|session|identity|principal|caller/i

function boundNames(id) {
	if (id.type === "Identifier") return [id.name]
	if (id.type === "ObjectPattern") return id.properties.flatMap(p => (p.value ? boundNames(p.value) : p.argument ? boundNames(p.argument) : []))
	return []
}

// what in this handler stands for the caller: req.user, res.locals, a helper's result,
// and every variable built from those (const data = auth.from(req), const filter = { owner: req.user.id })
// appendUserId() copies the caller into req.body, so req.body.UserId is the caller there
const APPENDS_USER = /(append|set|attach|inject|add)_?user/i
const BODY_USER_FIELD = /^(user_?id|owner_?id|owner)$/i

function identity(fn, route) {
	const { req, res } = handlerParams(fn)
	const names = new Set()
	const bodyIsCaller = route?.middleware.some(m => APPENDS_USER.test(m)) ?? false
	const isIdentity = n =>
		(isMember(n, req) && IDENTITY_KEYS.has(n.property.name)) ||
		(bodyIsCaller && isMemberNode(n) && isMember(n.object, req, "body") && BODY_USER_FIELD.test(n.property.name ?? "")) ||
		isMember(n, res, "locals") ||
		(n.type === "Identifier" && names.has(n.name)) ||
		(isCallNode(n) &&
			n.arguments.some(a => a.type === "Identifier" && a.name === req) &&
			IDENTITY_FN.test((isMemberNode(n.callee) ? `${n.callee.object.name ?? n.callee.object.property?.name ?? ""}.${n.callee.property.name}` : n.callee.name) ?? ""))
	const contains = node => {
		let found = false
		walk(node, n => {
			if (isIdentity(n)) found = true
		})
		return found
	}
	// twice, so a variable built from another identity variable is caught too
	for (let pass = 0; pass < 2; pass++) {
		walk(fn.body, n => {
			if (n.type !== "VariableDeclarator" || !n.init) return
			// const { user } = req
			const fromReq =
				n.id.type === "ObjectPattern" &&
				n.init.type === "Identifier" &&
				n.init.name === req &&
				n.id.properties.some(p => IDENTITY_KEYS.has(p.key?.name))
			if (fromReq || contains(n.init)) boundNames(n.id).forEach(name => names.add(name))
		})
	}
	return { names, contains }
}

export function readsIdentity(fn) {
	const { names, contains } = identity(fn)
	return names.size > 0 || contains(fn.body)
}

const ROLE_CALL = /^(require|assert|ensure|check|verify)_?(admin|role|permission|staff|owner)|^is_?(admin|staff|owner)$|^has_?(role|permission)|^authori[sz]e$|^can[A-Z]/i
const ROLE_FIELD = /^(is_?admin|admin|role|roles|permissions?|is_?staff)$/i

// a role checked inside the handler: requireAdmin(req, res), if (req.user.role !== "admin")
export function checksRoleInline(fn) {
	if (!fn) return false
	let found = false
	walk(fn.body, n => {
		if (isCallNode(n)) {
			const name = isMemberNode(n.callee) ? n.callee.property.name : n.callee.name
			if (name && ROLE_CALL.test(name)) found = true
		}
		if (isMemberNode(n) && ROLE_FIELD.test(n.property.name ?? "")) found = true
	})
	return found
}

// a credential in the body guards the action: a link password, a reset code
const CREDENTIAL_FIELD = /^(password|passcode|pin|code|otp|token|secret)$/i

export function checksBodyCredential(fn) {
	const { req } = handlerParams(fn)
	let found = false
	walk(fn.body, n => {
		if (isMemberNode(n) && isMember(n.object, req, "body") && CREDENTIAL_FIELD.test(n.property.name ?? "")) found = true
	})
	return found
}

export const hasRole = route => route.role || checksRoleInline(route.fn)

// findings point at the line in the handler, which may live in a controller file
export const whereOf = (route, line) => `${route.fnFile ?? route.file}:${line}`
