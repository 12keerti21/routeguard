import { readdirSync, readFileSync, existsSync, statSync } from "node:fs"
import path from "node:path"
import { parse } from "@babel/parser"

const METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "options", "head"])
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", "client", "test", "tests"])
const SOURCE = /\.(c|m)?(j|t)s$/

// role checks first: "adminAuth" is a role check, not just an auth check
const ROLE = /admin|role|permission|authori[sz]e|owner|rbac|acl|can[A-Z]|scope/i
const AUTH = /auth|jwt|token|protect|logged.?in|passport|session|guard/i

export function listSourceFiles(root) {
	const files = []
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		if (SKIP_DIRS.has(entry.name)) continue
		const full = path.join(root, entry.name)
		if (entry.isDirectory()) files.push(...listSourceFiles(full))
		else if (SOURCE.test(entry.name) && !entry.name.endsWith(".d.ts")) files.push(full)
	}
	return files
}

function parseFile(file) {
	try {
		return parse(readFileSync(file, "utf8"), {
			sourceType: "unambiguous",
			errorRecovery: true,
			plugins: ["jsx", "typescript", "decorators-legacy"]
		})
	} catch {
		return null
	}
}

export function walk(node, visit) {
	if (!node || typeof node.type !== "string") return
	visit(node)
	for (const key of Object.keys(node)) {
		if (key === "loc" || key === "start" || key === "end") continue
		const child = node[key]
		if (Array.isArray(child)) child.forEach(c => walk(c, visit))
		else if (child && typeof child.type === "string") walk(child, visit)
	}
}

function resolveModule(fromFile, spec) {
	if (!spec.startsWith(".")) return null
	const base = path.resolve(path.dirname(fromFile), spec)
	for (const ext of ["", ".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"]) {
		const candidate = base + ext
		if (existsSync(candidate) && statSync(candidate).isFile()) return candidate
	}
	return null
}

function stringValue(node) {
	if (!node) return null
	if (node.type === "StringLiteral") return node.value
	if (node.type === "TemplateLiteral" && node.expressions.length === 0) return node.quasis[0].value.cooked
	return null
}

function nameOf(node) {
	switch (node?.type) {
		case "Identifier":
			return node.name
		case "MemberExpression":
			return `${nameOf(node.object)}.${node.property.name ?? "?"}`
		case "CallExpression": {
			const args = node.arguments.map(a => stringValue(a) ?? nameOf(a) ?? "…")
			return `${nameOf(node.callee)}(${args.join(", ")})`
		}
		case "ArrowFunctionExpression":
		case "FunctionExpression":
			return "<inline>"
		default:
			return null
	}
}

// plumbing, not access control
const NOISE = /^(cors|vhost|morgan|compression|helmet|cookieParser|bodyParser|express\.(json|urlencoded|static|text|raw))\b/

// [auth, admin] and auth, admin both mean two middlewares
function flattenMiddleware(args) {
	return args
		.flatMap(a => (a.type === "ArrayExpression" ? a.elements : [a]))
		.map(nameOf)
		.filter(name => name && !NOISE.test(name))
}

function scanFile(file) {
	const ast = parseFile(file)
	const result = { file, requires: new Map(), mounts: [], routes: [], uses: [], functions: new Map() }
	if (!ast) return result

	walk(ast, node => {
		// named handlers: function getBook(req, res) {} or const getBook = (req, res) => {}
		if (node.type === "FunctionDeclaration" && node.id) result.functions.set(node.id.name, node)
		if (
			node.type === "VariableDeclarator" &&
			node.id.type === "Identifier" &&
			["ArrowFunctionExpression", "FunctionExpression"].includes(node.init?.type)
		) {
			result.functions.set(node.id.name, node.init)
		}

		// const users = require("../routes/users")
		if (
			node.type === "VariableDeclarator" &&
			node.id.type === "Identifier" &&
			node.init?.type === "CallExpression" &&
			node.init.callee.name === "require"
		) {
			const target = resolveModule(file, stringValue(node.init.arguments[0]) ?? "")
			if (target) result.requires.set(node.id.name, target)
		}
		// import users from "../routes/users.js"
		if (node.type === "ImportDeclaration") {
			const target = resolveModule(file, node.source.value)
			const def = node.specifiers.find(s => s.type === "ImportDefaultSpecifier")
			if (target && def) result.requires.set(def.local.name, target)
		}

		if (node.type !== "CallExpression" || node.callee.type !== "MemberExpression") return
		const method = node.callee.property.name
		const owner = nameOf(node.callee.object)
		const line = node.loc.start.line
		const [first, ...rest] = node.arguments
		const routePath = stringValue(first)

		if (method === "use") {
			if (routePath !== null) {
				// app.use("/api/users", auth, users): the last identifier is the mounted router
				const last = rest.at(-1)
				const target = last?.type === "Identifier" ? last.name : null
				result.mounts.push({ owner, prefix: routePath, target, middleware: flattenMiddleware(rest.slice(0, -1)), line })
			} else {
				result.uses.push({ owner, middleware: flattenMiddleware(node.arguments), line })
			}
			return
		}

		if (METHODS.has(method) && routePath !== null && rest.length > 0) {
			result.routes.push({
				owner,
				method: method.toUpperCase(),
				path: routePath,
				middleware: flattenMiddleware(rest.slice(0, -1)),
				handler: nameOf(rest.at(-1)) ?? "?",
				handlerNode: rest.at(-1),
				line
			})
		}
	})
	return result
}

function joinPath(prefix, routePath) {
	const joined = `${prefix}/${routePath}`.replace(/\/+/g, "/")
	return joined.length > 1 ? joined.replace(/\/$/, "") : joined
}

export function classify(middleware) {
	const role = middleware.some(m => ROLE.test(m))
	const auth = role || middleware.some(m => AUTH.test(m))
	return { auth, role }
}

export function mapRoutes(root) {
	const scans = listSourceFiles(root).map(scanFile)
	const byFile = new Map(scans.map(s => [s.file, s]))

	// who mounts each file, with what prefix and mount-level middleware
	const mountedBy = new Map()
	for (const scan of scans) {
		for (const mount of scan.mounts) {
			const target = scan.requires.get(mount.target)
			if (!target || !byFile.has(target)) continue
			if (!mountedBy.has(target)) mountedBy.set(target, [])
			mountedBy.get(target).push({ parent: scan.file, ...mount })
		}
	}

	// a file can be mounted at several prefixes, through nested routers
	function contexts(file, seen = new Set()) {
		const parents = mountedBy.get(file)
		if (!parents || seen.has(file)) return [{ prefix: "", middleware: [] }]
		seen.add(file)
		return parents.flatMap(m =>
			contexts(m.parent, new Set(seen)).map(ctx => ({
				prefix: joinPath(ctx.prefix, m.prefix),
				middleware: [...ctx.middleware, ...inheritedUses(byFile.get(m.parent), m.owner, m.line), ...m.middleware]
			}))
		)
	}

	// router.use(auth) applies to routes registered after it on the same object
	function inheritedUses(scan, owner, line) {
		return scan.uses.filter(u => u.owner === owner && u.line < line).flatMap(u => u.middleware)
	}

	const routes = []
	for (const scan of scans) {
		for (const route of scan.routes) {
			for (const ctx of contexts(scan.file)) {
				const middleware = [...ctx.middleware, ...inheritedUses(scan, route.owner, route.line), ...route.middleware]
				const node = route.handlerNode
				const fn = node?.type === "Identifier" ? scan.functions.get(node.name) : node
				const entry = {
					method: route.method,
					path: joinPath(ctx.prefix, route.path),
					middleware,
					handler: route.handler,
					...classify(middleware),
					file: path.relative(root, scan.file),
					line: route.line
				}
				// kept off JSON output: rules read the handler's AST
				Object.defineProperty(entry, "fn", { value: fn?.body ? fn : null })
				routes.push(entry)
			}
		}
	}
	return routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
}
