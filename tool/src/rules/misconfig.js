import path from "node:path"
import { listSourceFiles, parseFile, walk, isCallNode, isMemberNode } from "../mapper.js"
import { calleeName, calleeObject } from "./handler.js"

const ASYMMETRIC = /^(RS|ES|PS)\d{3}$|^EdDSA$/
const SYMMETRIC = /^HS\d{3}$/
const FUNCTION = /^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ObjectMethod|ClassMethod)$/
const ERROR_NAME = /^(e|err|error|ex|exception)$/
const SECURITY_HEADERS = /^(helmet|lusca|xssProtection|hidePoweredBy|frameguard|hsts|contentSecurityPolicy)$/

const prop = (object, key) =>
	object?.type === "ObjectExpression" ? object.properties.find(p => (p.key?.name ?? p.key?.value) === key)?.value : undefined
const stringsIn = node => (node?.type === "ArrayExpression" ? node.elements.filter(e => e?.type === "StringLiteral").map(e => e.value) : [])
const isTrue = node => node?.type === "BooleanLiteral" && node.value

// reflects the caller's origin: origin: true, origin: "*", or (origin, cb) => cb(null, true)
function anyOrigin(origin) {
	if (!origin) return false
	if (isTrue(origin) || (origin.type === "StringLiteral" && origin.value === "*")) return true
	if (["ArrowFunctionExpression", "FunctionExpression"].includes(origin.type)) {
		let allowsAll = false
		walk(origin.body, n => {
			if (isCallNode(n) && n.arguments.length === 2 && isTrue(n.arguments[1]) && n.arguments[0].type === "NullLiteral") allowsAll = true
		})
		// a callback that only ever says yes, with no list or check in front of it
		let checks = false
		walk(origin.body, n => {
			if (n.type === "IfStatement" || n.type === "ConditionalExpression" || (isCallNode(n) && /includes|indexOf|test|has|match/.test(calleeName(n)))) checks = true
		})
		return allowsAll && !checks
	}
	return false
}

// API8 (and API2 for tokens): settings that hold for the whole app, read once per file
export function misconfig(root) {
	const findings = []
	let createsApp = null
	let hasSecurityHeaders = false
	const add = (file, node, finding) =>
		findings.push({ ...finding, route: "(app-wide)", where: `${path.relative(root, file)}:${node.loc.start.line}` })

	for (const file of listSourceFiles(root)) {
		const ast = parseFile(file)
		if (!ast) continue
		let rawErrors = 0
		let firstRawError = null
		// CORS headers, grouped by the function that sets them
		const corsByFunction = new Map()
		let corsNoOptions = false

		// the walk visits a function before its body, so this stack holds the nearest one
		const enclosing = []
		walk(ast, n => {
			if (FUNCTION.test(n.type)) {
				while (enclosing.length && !(enclosing.at(-1).start <= n.start && n.end <= enclosing.at(-1).end)) enclosing.pop()
				enclosing.push(n)
				return
			}
			while (enclosing.length && !(enclosing.at(-1).start <= n.start && n.end <= enclosing.at(-1).end)) enclosing.pop()
			if (!isCallNode(n)) return
			const name = calleeName(n)
			const object = calleeObject(n)

			if (n.callee.type === "Identifier" && name === "express" && !createsApp) createsApp = { file, node: n }
			if (SECURITY_HEADERS.test(name) || SECURITY_HEADERS.test(object)) hasSecurityHeaders = true
			if (name === "disable" && n.arguments[0]?.value === "x-powered-by") hasSecurityHeaders = true

			// cors() and cors({ origin, credentials })
			if (name === "cors" && n.callee.type === "Identifier") {
				const options = n.arguments[0]
				if (!options) {
					if (corsNoOptions) return
					corsNoOptions = true
					add(file, n, {
						rule: "CORS",
						owasp: "API8:2023 Security Misconfiguration",
						severity: "LOW",
						message: "cors() with no options answers every origin. Fine for a public, token-only API; not with cookies or for internal APIs.",
						fix: "Pass the origins that may call the API: cors({ origin: ['https://app.example.com'] })."
					})
				} else if (anyOrigin(prop(options, "origin")) && isTrue(prop(options, "credentials"))) {
					add(file, n, {
						rule: "CORS",
						owasp: "API8:2023 Security Misconfiguration",
						severity: "HIGH",
						message: "CORS reflects any origin and allows credentials, so any website can make signed-in requests and read the answers.",
						fix: "List the allowed origins explicitly; never combine credentials: true with a reflected or * origin."
					})
				}
			}

			// res.setHeader("Access-Control-Allow-Origin", "*" or req.headers.origin)
			if (/^(setHeader|header|set)$/.test(name) && /^access-control-allow-(origin|credentials)$/i.test(n.arguments[0]?.value ?? "")) {
				const header = n.arguments[0].value.toLowerCase()
				const value = n.arguments[1]
				const fn = enclosing.at(-1) ?? ast
				if (!corsByFunction.has(fn)) corsByFunction.set(fn, { credentials: false, wildcard: null })
				const group = corsByFunction.get(fn)
				if (header.endsWith("credentials") && (isTrue(value) || value?.value === "true")) group.credentials = true
				const reflected = isMemberNode(value) && /origin/i.test(value.property?.name ?? value.property?.value ?? "")
				if (header.endsWith("origin") && (value?.value === "*" || reflected)) group.wildcard ??= { node: n, reflected }
			}

			// jwt.verify(token, key, { algorithms, ignoreExpiration }) and jwt.sign(payload, "literal")
			if (object === "jwt" || object === "jsonwebtoken") {
				const secret = n.arguments[1]
				if (/^(sign|verify)$/.test(name) && (secret?.type === "StringLiteral" || (secret?.type === "TemplateLiteral" && secret.expressions.length === 0))) {
					add(file, n, {
						rule: "JWT",
						owasp: "API2:2023 Broken Authentication",
						severity: "HIGH",
						message: `jwt.${name}() uses a key written in the code, so anyone with the source can mint tokens.`,
						fix: "Load the key from the environment or a secret store, and rotate the one in the code."
					})
				}
				const options = n.arguments[2]
				const algorithms = stringsIn(prop(options, "algorithms"))
				if (name === "verify" && algorithms.some(a => ASYMMETRIC.test(a)) && algorithms.some(a => SYMMETRIC.test(a))) {
					add(file, n, {
						rule: "JWT",
						owasp: "API2:2023 Broken Authentication",
						severity: "HIGH",
						message: `jwt.verify() accepts both ${algorithms.join(" and ")}: a token signed with HS256 using the public key as the secret passes (algorithm confusion).`,
						fix: "Accept exactly the algorithm you sign with, e.g. { algorithms: ['RS256'] }."
					})
				}
				if (name === "verify" && algorithms.some(a => a.toLowerCase() === "none")) {
					add(file, n, {
						rule: "JWT",
						owasp: "API2:2023 Broken Authentication",
						severity: "HIGH",
						message: "jwt.verify() accepts alg none, so an unsigned token passes.",
						fix: "Remove 'none' from algorithms."
					})
				}
				if (name === "verify" && isTrue(prop(options, "ignoreExpiration"))) {
					add(file, n, {
						rule: "JWT",
						owasp: "API2:2023 Broken Authentication",
						severity: "MEDIUM",
						message: "jwt.verify() ignores expiry, so a stolen token works forever.",
						fix: "Drop ignoreExpiration and keep access tokens short-lived."
					})
				}
			}

			// res.json({ err }) / res.send(err.stack): internals in the answer
			if (/^(send|json)$/.test(name)) {
				let stack = null
				let raw = false
				for (const arg of n.arguments) {
					walk(arg, a => {
						if (isMemberNode(a) && a.property?.name === "stack") stack = a
					})
					if (arg.type === "Identifier" && ERROR_NAME.test(arg.name)) raw = true
					if (arg.type === "ObjectExpression" && arg.properties.some(p => p.value?.type === "Identifier" && ERROR_NAME.test(p.value.name))) raw = true
				}
				if (stack) {
					add(file, n, {
						rule: "ERROR_LEAK",
						owasp: "API8:2023 Security Misconfiguration",
						severity: "MEDIUM",
						message: "A stack trace goes back to the client, showing file paths, library versions and code structure.",
						fix: "Log the stack on the server and answer with a generic message and an error id."
					})
				} else if (raw) {
					rawErrors++
					firstRawError ??= n
				}
			}
		})

		for (const { wildcard, credentials } of corsByFunction.values()) {
			if (!wildcard) continue
			add(file, wildcard.node, {
				rule: "CORS",
				owasp: "API8:2023 Security Misconfiguration",
				severity: credentials ? "HIGH" : "LOW",
				message: `Access-Control-Allow-Origin is ${wildcard.reflected ? "copied from the request" : "*"}${credentials ? ", with Allow-Credentials true, so any website can act as the signed-in user" : ""}.`,
				fix: "Answer only the origins you trust."
			})
		}
		if (rawErrors) {
			add(file, firstRawError, {
				rule: "ERROR_LEAK",
				owasp: "API8:2023 Security Misconfiguration",
				severity: "LOW",
				message: `${rawErrors} response${rawErrors > 1 ? "s" : ""} in this file send a raw error object, which can carry query details, driver messages and paths.`,
				fix: "Map errors to a fixed code and message before answering."
			})
		}
	}

	if (createsApp && !hasSecurityHeaders) {
		add(createsApp.file, createsApp.node, {
			rule: "SECURITY_HEADERS",
			owasp: "API8:2023 Security Misconfiguration",
			severity: "LOW",
			message: "No helmet() or equivalent: no HSTS, nosniff or frame protection, and X-Powered-By names the framework.",
			fix: "app.use(helmet()), or at least app.disable('x-powered-by') and the headers your clients need."
		})
	}
	return findings
}
