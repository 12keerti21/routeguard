import path from "node:path"
import { listSourceFiles, parseFile, walk, isCallNode, isMemberNode } from "../mapper.js"
import { DB_WRITE, calleeName, calleeObject } from "./handler.js"

const CLIENT_FN = new Set(["fetch", "axios", "got", "needle", "request", "superagent"])
const CLIENT_OBJ = new Set(["axios", "got", "needle", "request", "superagent", "http", "https", "undici", "ky"])
const CLIENT_METHOD = /^(get|post|put|patch|delete|head|request|stream)$/
// schema.parse(data), validate(data), Joi, zod, ajv: the response is checked before use
const VALIDATE = /validat|parse|safeParse|schema|assert|sanitiz|check|verify|decode|joi|zod|ajv|yup/i
const CODE_SINK = /^(eval|Function|runInContext|runInNewContext|runInThisContext|exec|execSync|spawn|spawnSync|execFile)$/
// a key in a literal URL: ?appid=2ee846af…, &api_key=…
const KEY_IN_URL = /[?&](app_?id|api_?key|key|token|access_token|secret|client_secret)=([A-Za-z0-9_\-]{16,})/i
const LOCAL = /^http:\/\/(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|[\w-]+:\d+\/?$|[\w-]+\/)/i

const isClientCall = n =>
	isCallNode(n) && (CLIENT_FN.has(n.callee.name) || (CLIENT_OBJ.has(calleeObject(n)) && CLIENT_METHOD.test(calleeName(n))))
const isFunction = n => ["ArrowFunctionExpression", "FunctionExpression"].includes(n?.type)
const literalText = n =>
	n?.type === "StringLiteral" ? n.value : n?.type === "TemplateLiteral" ? n.quasis.map(q => q.value.cooked).join("…") : null

// each outermost function is its own scope, so two functions' "message" never mix
function scopes(ast) {
	const out = []
	const visit = node => {
		if (!node || typeof node.type !== "string") return
		if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod"].includes(node.type)) {
			out.push(node)
			return
		}
		for (const key of Object.keys(node)) {
			if (key === "loc" || key === "start" || key === "end") continue
			const child = node[key]
			if (Array.isArray(child)) child.forEach(visit)
			else if (child && typeof child.type === "string") visit(child)
		}
	}
	visit(ast.program)
	return out
}

// reads third-party data, unless it went through a validator: schema.parse(res.data) is clean
function reads(node, names) {
	if (!node || typeof node.type !== "string") return false
	if (isCallNode(node) && VALIDATE.test(calleeName(node))) return false
	if (node.type === "Identifier") return names.has(node.name)
	if (isClientCall(node)) return true
	for (const key of Object.keys(node)) {
		if (key === "loc" || key === "start" || key === "end") continue
		const child = node[key]
		if (Array.isArray(child) ? child.some(c => reads(c, names)) : child && typeof child.type === "string" && reads(child, names)) return true
	}
	return false
}

// API10: data from another API is trusted as if it were our own
export function consumption(root) {
	const findings = []
	const add = (file, node, finding) =>
		findings.push({ ...finding, route: "(app-wide)", where: `${path.relative(root, file)}:${node.loc.start.line}` })

	for (const file of listSourceFiles(root)) {
		const ast = parseFile(file)
		if (!ast) continue

		// literal values of variables in the file: const url = `https://…?appid=…`
		const inits = new Map()
		walk(ast, n => {
			if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init) inits.set(n.id.name, n.init)
		})

		for (const scope of scopes(ast)) {
		// what came back from a third party: const r = await axios.get(…), .then(r => …),
		// https.get(url, res => res.on("data", chunk => body += chunk)), and values built from those
		const external = new Set()
		const taintParams = fn => fn?.params?.forEach(p => p.type === "Identifier" && external.add(p.name))
		for (let pass = 0; pass < 3; pass++) {
			walk(scope, n => {
				if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init && reads(n.init, external)) external.add(n.id.name)
				if (n.type === "AssignmentExpression" && n.left.type === "Identifier" && reads(n.right, external)) external.add(n.left.name)
				if (isClientCall(n)) n.arguments.filter(isFunction).forEach(taintParams)
				if (isCallNode(n) && isMemberNode(n.callee) && /^(then|on|once)$/.test(calleeName(n))) {
					const source = n.callee.object
					if (isClientCall(source) || (source.type === "Identifier" && external.has(source.name)) || reads(source, external))
						n.arguments.filter(isFunction).forEach(taintParams)
				}
			})
		}

		const validated = new Set()
		walk(scope, n => {
			if (isCallNode(n) && VALIDATE.test(calleeName(n)))
				n.arguments.forEach(a => walk(a, x => x.type === "Identifier" && external.has(x.name) && validated.add(x.name)))
		})
		const unchecked = new Set([...external].filter(name => !validated.has(name)))

		let relayed = null
		let stored = null
		walk(scope, n => {
			if (!isCallNode(n)) return
			const name = calleeName(n)
			const args = n.arguments.filter(a => !isFunction(a))

			if (isClientCall(n)) {
				const first = n.arguments[0]
				const url = literalText(first?.type === "Identifier" ? inits.get(first.name) : first)
				const key = url?.match(KEY_IN_URL)
				if (key)
					add(file, n, {
						rule: "SECRET_IN_URL",
						owasp: "API8:2023 Security Misconfiguration",
						severity: "HIGH",
						message: `The "${key[1]}" key for a third-party API is written into the URL in the code.`,
						fix: "Load the key from the environment or a secret store, and rotate the one in the code."
					})
				if (url?.startsWith("http://") && !LOCAL.test(url))
					add(file, n, {
						rule: "UNSAFE_CONSUMPTION",
						owasp: "API10:2023 Unsafe Consumption of APIs",
						severity: "LOW",
						message: `A third-party API is called over plain http (${url.slice(0, 60)}), so its answers can be changed in transit.`,
						fix: "Use https, and verify certificates."
					})
			}
			if (unchecked.size === 0 || !args.some(a => reads(a, unchecked))) return

			if (CODE_SINK.test(name) || (n.callee.type === "Identifier" && name === "Function")) {
				add(file, n, {
					rule: "UNSAFE_CONSUMPTION",
					owasp: "API10:2023 Unsafe Consumption of APIs",
					severity: "HIGH",
					message: `${name}() runs data that came from another API, so whoever controls that API runs code here.`,
					fix: "Never evaluate third-party data; parse it as data and validate it against a schema."
				})
			} else if (name === "redirect") {
				add(file, n, {
					rule: "UNSAFE_CONSUMPTION",
					owasp: "API10:2023 Unsafe Consumption of APIs",
					severity: "MEDIUM",
					message: "The client is redirected to a URL another API returned, which that API can point anywhere.",
					fix: "Redirect only to URLs on an allow-list."
				})
			} else if (DB_WRITE.test(name)) stored ??= n
			else if (/^(send|write|end)$/.test(name) && isMemberNode(n.callee)) relayed ??= n
		})
		if (stored)
			add(file, stored, {
				rule: "UNSAFE_CONSUMPTION",
				owasp: "API10:2023 Unsafe Consumption of APIs",
				severity: "MEDIUM",
				message: `${calleeName(stored)}() stores data from another API without validating it, so a compromised or buggy provider writes into our database.`,
				fix: "Validate the response against a schema (zod, Joi, ajv) and copy only the fields you need."
			})
		if (relayed)
			add(file, relayed, {
				rule: "UNSAFE_CONSUMPTION",
				owasp: "API10:2023 Unsafe Consumption of APIs",
				severity: "LOW",
				message: "A third-party response is passed to our clients as is, so its content (HTML, scripts, extra fields) reaches them under our origin.",
				fix: "Parse the response, pick the fields you need and send those as JSON."
			})
		}
	}
	return findings
}
