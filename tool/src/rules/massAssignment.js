import { walk, isMemberNode, isCallNode } from "../mapper.js"
import { handlerParams, isMember, whereOf } from "./handler.js"

const WRITE_CALL =
	/^(create|insert|insertOne|insertMany|upsert|build|bulkCreate|update|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate|replaceOne|set|assign)$/

// models and routes where an extra field like role or isAdmin means privilege escalation
const PRIVILEGED = /user|account|member|profile|admin|register|signup/i

// names bound to the whole body: const data = req.body
function bodyAliases(fn, req) {
	const names = new Set()
	walk(fn.body, n => {
		if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && isMember(n.init, req, "body"))
			names.add(n.id.name)
	})
	return names
}

// req.body itself, an alias of it, or { ...req.body } / { $set: req.body }
function isWholeBody(node, req, aliases) {
	if (isMember(node, req, "body")) return true
	if (node?.type === "Identifier" && aliases.has(node.name)) return true
	if (node?.type === "ObjectExpression")
		return node.properties.some(p =>
			p.type === "SpreadElement" ? isWholeBody(p.argument, req, aliases) : isWholeBody(p.value, req, aliases)
		)
	return false
}

// fields a client must never choose
const SENSITIVE_FIELD = /^(is_?admin|admin|role|roles|permissions?|is_?verified|verified|credit|balance|owner|owner_?id|user_?id|tenant_?id|org_?id)$/i

// { isAdmin: req.body.isAdmin }: a privileged field copied from the body by name
function sensitiveFieldsFromBody(node, req) {
	if (node?.type !== "ObjectExpression") return []
	return node.properties
		.filter(p => p.type === "ObjectProperty" && SENSITIVE_FIELD.test(p.key.name ?? p.key.value ?? ""))
		.filter(p => isMemberNode(p.value) && isMember(p.value.object, req, "body"))
		.map(p => p.key.name ?? p.key.value)
}

function calleeName(node) {
	if (node.callee.type === "Identifier") return node.callee.name
	if (isMemberNode(node.callee)) return node.callee.property.name
	return ""
}

// API3: the whole request body is written to a record, so a client can set fields the
// form never offered (role, isAdmin, credit, owner)
export function massAssignment(route) {
	if (!route.fn || route.method === "GET") return null
	const { req } = handlerParams(route.fn)
	const aliases = bodyAliases(route.fn, req)

	const sinks = []
	const fields = []
	walk(route.fn.body, node => {
		if (node.type === "NewExpression" || (isCallNode(node) && WRITE_CALL.test(calleeName(node)))) {
			for (const arg of node.arguments) {
				const found = sensitiveFieldsFromBody(arg, req)
				if (found.length) fields.push({ names: found, line: node.loc.start.line })
			}
		}
		if (node.type === "NewExpression" && node.arguments.some(a => isWholeBody(a, req, aliases)))
			sinks.push({ what: `new ${calleeName(node)}(…)`, model: calleeName(node), line: node.loc.start.line })
		if (isCallNode(node) && WRITE_CALL.test(calleeName(node))) {
			if (node.arguments.some(a => isWholeBody(a, req, aliases))) {
				const object = isMemberNode(node.callee) ? (node.callee.object.name ?? "") : ""
				sinks.push({ what: `${object ? object + "." : ""}${calleeName(node)}(…)`, model: object, line: node.loc.start.line })
			}
		}
	})
	if (sinks.length === 0 && fields.length > 0) {
		const names = [...new Set(fields.flatMap(f => f.names))]
		return {
			rule: "MASS_ASSIGNMENT",
			owasp: "API3:2023 Broken Object Property Level Authorization",
			severity: "HIGH",
			route: `${route.method} ${route.path}`,
			where: whereOf(route, fields[0].line),
			message: `${names.join(", ")} is taken straight from the request body, so a client chooses its own privileges.`,
			fix: `Set ${names.join(", ")} on the server (a default, or from req.user), never from req.body.`
		}
	}
	if (sinks.length === 0) return null

	const privileged = sinks.some(s => PRIVILEGED.test(s.model)) || PRIVILEGED.test(route.path)
	return {
		rule: "MASS_ASSIGNMENT",
		owasp: "API3:2023 Broken Object Property Level Authorization (mass assignment)",
		// behind a role check the caller is trusted more, but extra fields still deserve a look
		severity: route.role ? "LOW" : privileged ? "HIGH" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: whereOf(route, sinks[0].line),
		message: `${sinks.map(s => s.what).join(", ")} receives the whole request body, so a client can set any field${privileged ? ", including role or admin flags" : ""}.`,
		fix: "Copy only the fields the client may set: _.pick(req.body, ['name', 'email']) or a validator schema that strips unknown keys."
	}
}
