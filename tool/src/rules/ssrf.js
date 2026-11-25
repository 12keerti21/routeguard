import { walk, isCallNode } from "../mapper.js"
import { calleeName, calleeObject, userInput, whereOf } from "./handler.js"

const CLIENT_FN = new Set(["fetch", "axios", "got", "needle", "request", "superagent"])
const CLIENT_OBJ = new Set(["axios", "got", "needle", "request", "superagent", "http", "https", "undici", "ky"])
const CLIENT_METHOD = /^(get|post|put|patch|delete|head|request|stream)$/
// a check on the URL before the request: isAllowedHost(url), validateUrl(url)
const URL_CHECK = /allow|whitelist|safe.?url|is.?safe|validate.?url|is.?allowed|trusted|permitted/i
// `https://api.example.com/x?q=${input}`: the host is fixed, the client only fills a parameter
const FIXED_HOST = /^https?:\/\/[^/${}]+\//i

const isClientCall = n =>
	CLIENT_FN.has(n.callee.name) || (CLIENT_OBJ.has(calleeObject(n)) && CLIENT_METHOD.test(calleeName(n)))

const isFunction = n => ["ArrowFunctionExpression", "FunctionExpression"].includes(n?.type)

function fixedHost(node, inits) {
	const value = node?.type === "Identifier" ? inits.get(node.name) : node
	if (value?.type === "TemplateLiteral") return FIXED_HOST.test(value.quasis[0].value.cooked)
	if (value?.type === "BinaryExpression") return value.left.type === "StringLiteral" ? FIXED_HOST.test(value.left.value) : fixedHost(value.left, inits)
	return false
}

// API7: the server fetches a URL the client chose, so it can be pointed at internal services
// or the cloud metadata endpoint
export function ssrf(route) {
	if (!route.fn) return null
	const { reads, inits } = userInput(route.fn)

	const hits = []
	let checked = false
	walk(route.fn.body, n => {
		if (!isCallNode(n)) return
		if (URL_CHECK.test(calleeName(n)) && n.arguments.some(reads)) checked = true
		if (!isClientCall(n)) return
		const tainted = n.arguments.find(a => !isFunction(a) && reads(a))
		if (tainted) hits.push({ call: n, arg: tainted })
	})
	if (hits.length === 0 || checked) return null

	const [hit] = hits
	const fixed = fixedHost(hit.arg, inits)
	const client = `${calleeObject(hit.call) ? calleeObject(hit.call) + "." : ""}${calleeName(hit.call)}`
	return {
		rule: "SSRF",
		owasp: "API7:2023 Server Side Request Forgery",
		severity: fixed ? "MEDIUM" : "HIGH",
		route: `${route.method} ${route.path}`,
		where: whereOf(route, hit.call.loc.start.line),
		message: fixed
			? `${client}() puts client input into a fixed host's URL, so the client can change the path or add parameters.`
			: `${client}() requests a URL the client controls, so the server can be sent to internal hosts or 169.254.169.254.`,
		fix: fixed
			? "Encode the value (encodeURIComponent) and validate it against what the API expects."
			: "Allow only known hosts: parse with new URL(), check url.hostname against an allow-list, and block private and link-local addresses."
	}
}
