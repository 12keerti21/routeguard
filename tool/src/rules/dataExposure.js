import { readFileSync } from "node:fs"
import { walk, isCallNode, isMemberNode } from "../mapper.js"
import { DB_CALL, calleeName, handlerParams, hasRole, isMember, whereOf } from "./handler.js"

// models whose documents carry password hashes, tokens and personal data
const PERSON_MODEL = /^(user|users|account|accounts|member|members|customer|customers|profile|profiles|employee|employees|person|people)$/i
// field selection on the query: .select("name email"), { attributes: [...] }, { select: {...} }
const PROJECTION_CALL = /^(select|project|projection|attributes|pick|omit|lean)$/
const PROJECTION_KEY = /^(select|attributes|projection|fields)$/
// shaping before the response: toJSON, a DTO, a serializer, _.pick
const SHAPED = /pick|omit|serial|sanitiz|transform|toJSON|toDTO|dto|format|present|public|safe|strip|without/i
// the model hides fields itself: select: false on a field, a toJSON transform
const MODEL_HIDES = /select:\s*false|toJSON|transform\s*[:(]|defaultScope|hidden/

function modelFrom(call) {
	let node = call.callee
	while (isMemberNode(node) || isCallNode(node)) node = isMemberNode(node) ? node.object : node.callee
	return node?.type === "Identifier" ? node.name : null
}

// User.findById(id) and User.find().select("name"): the query, and whether it picks fields
function personQuery(node) {
	let query = null
	let projected = false
	walk(node, n => {
		if (!isCallNode(n)) return
		const name = calleeName(n)
		if (PROJECTION_CALL.test(name)) projected = true
		if (DB_CALL.test(name) && PERSON_MODEL.test(modelFrom(n) ?? "")) {
			query = n
			// findById(id, "name email") or findOne(filter, { password: 0 }) or { attributes: [...] }
			const options = n.arguments.slice(1)
			if (options.some(a => a.type === "StringLiteral" || a.type === "ObjectExpression")) projected = true
			for (const arg of n.arguments)
				if (arg.type === "ObjectExpression" && arg.properties.some(p => PROJECTION_KEY.test(p.key?.name ?? ""))) projected = true
		}
	})
	return query ? { query, projected } : null
}

function modelHidesFields(route, model) {
	const file = route.importedFile?.(route.fnPath, model)
	try {
		return file ? MODEL_HIDES.test(readFileSync(file, "utf8")) : false
	} catch {
		return false
	}
}

const isResponse = (n, res) =>
	isCallNode(n) &&
	isMemberNode(n.callee) &&
	/^(send|json|jsonp)$/.test(n.callee.property.name) &&
	(isMember(n.callee, res) || isCallNode(n.callee.object))

// the record itself, not one of its fields: user, { user }, { ...user }, JSON.stringify(user)
function sendsWhole(node, names) {
	if (!node) return false
	if (node.type === "Identifier") return names.has(node.name)
	if (node.type === "ObjectExpression")
		return node.properties.some(p => (p.type === "SpreadElement" ? sendsWhole(p.argument, names) : sendsWhole(p.value, names)))
	if (node.type === "ArrayExpression") return node.elements.some(e => sendsWhole(e, names))
	if (isCallNode(node)) return !SHAPED.test(calleeName(node)) && calleeName(node) === "stringify" && node.arguments.some(a => sendsWhole(a, names))
	return false
}

// API3: a person's whole record goes back to the client, password hash and tokens included
export function dataExposure(route) {
	if (!route.fn) return null
	const { res } = handlerParams(route.fn)

	const records = new Map()
	walk(route.fn.body, n => {
		// const user = await User.findById(id)
		if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init) {
			const found = personQuery(n.init)
			if (found && !found.projected) records.set(n.id.name, found)
		}
		// User.findById(id).then(user => res.json({ user }))
		if (isCallNode(n) && calleeName(n) === "then" && isMemberNode(n.callee)) {
			const found = personQuery(n.callee.object)
			const param = n.arguments[0]?.params?.[0]
			if (found && !found.projected && param?.type === "Identifier") records.set(param.name, found)
		}
	})
	if (records.size === 0) return null

	let sent = null
	walk(route.fn.body, n => {
		if (!sent && isResponse(n, res) && n.arguments.some(a => sendsWhole(a, new Set(records.keys())))) sent = n
	})
	if (!sent) return null

	const [record] = [...records.values()]
	const model = modelFrom(record.query)
	if (modelHidesFields(route, model)) return null

	return {
		rule: "DATA_EXPOSURE",
		owasp: "API3:2023 Broken Object Property Level Authorization (excessive data exposure)",
		severity: !route.auth ? "HIGH" : hasRole(route) ? "LOW" : "MEDIUM",
		route: `${route.method} ${route.path}`,
		where: whereOf(route, sent.loc.start.line),
		message: `The whole ${model} record from ${calleeName(record.query)} is sent to the client, with no field selection, so hashes, tokens and private fields go too.`,
		fix: `Select only what the client needs: ${model}.${calleeName(record.query)}(…).select("name email"), _.pick(user, [...]), or mark secret fields select: false in the schema.`
	}
}
