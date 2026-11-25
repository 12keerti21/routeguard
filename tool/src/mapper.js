import { readdirSync, readFileSync, existsSync, statSync } from "node:fs"
import path from "node:path"
import { parse } from "@babel/parser"

const METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "options", "head"])
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", "client", "test", "tests", "__tests__"])
const SOURCE = /\.(c|m)?(j|t)s$/

// role checks first: "adminAuth" is a role check, not just an auth check
const ROLE = /admin|role|permission|authori[sz]e|owner|rbac|acl|can[A-Z]|scope/i
// auth('manageUsers'), permit('editor'): a guard called with the right it demands
const PERMISSION_CALL = /(^|\.)(auth|permit|allow|can|requires?|guard)\((?!\))/i
const AUTH = /auth|jwt|token|(^|\.)protect(ed)?\b|logged.?in|guard|verify/i
// present in the chain but enforces nothing
const NOT_ENFORCED = /optional|initialize|session\(/i

export function listSourceFiles(root) {
	const files = []
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		if (SKIP_DIRS.has(entry.name)) continue
		const full = path.join(root, entry.name)
		if (entry.isDirectory()) files.push(...listSourceFiles(full))
		else if (SOURCE.test(entry.name) && !/\.(d|test|spec)\.(j|t)s$/.test(entry.name)) files.push(full)
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

// a.b and a?.b, a() and a?.()
export const isMemberNode = node => node?.type === "MemberExpression" || node?.type === "OptionalMemberExpression"
export const isCallNode = node => node?.type === "CallExpression" || node?.type === "OptionalCallExpression"
const isFunctionNode = node => ["ArrowFunctionExpression", "FunctionExpression", "FunctionDeclaration"].includes(node?.type)

function resolveModule(fromFile, spec) {
	if (!spec?.startsWith(".")) return null
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
	if (isMemberNode(node)) return `${nameOf(node.object)}.${node.property.name ?? "?"}`
	if (isCallNode(node)) {
		const args = node.arguments.map(a => stringValue(a) ?? nameOf(a) ?? "…")
		return `${nameOf(node.callee)}(${args.join(", ")})`
	}
	if (node?.type === "Identifier") return node.name
	if (isFunctionNode(node)) return "<inline>"
	return null
}

// catchAsync(async (req, res) => {}) and asyncHandler(getUser) wrap the real handler
function unwrapHandler(node) {
	if (isCallNode(node)) {
		const inner = node.arguments.find(a => isFunctionNode(a) || a.type === "Identifier" || isMemberNode(a))
		return inner ? unwrapHandler(inner) : node
	}
	return node
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

// router.route("/x").get(…).post(…): the path sits on .route(), down the chain
function routeChainPath(object) {
	let node = object
	while (isCallNode(node) && isMemberNode(node.callee)) {
		const prop = node.callee.property.name
		if (prop === "route") return stringValue(node.arguments[0])
		if (!METHODS.has(prop)) return null
		node = node.callee.object
	}
	return null
}

// Router().use(a).use(b) and router.route("/x").get(…): the object at the root of the chain
function chainRootNode(object) {
	let node = object
	while (isCallNode(node) && isMemberNode(node.callee) && /^(use|route|get|post|put|patch|delete|all)$/.test(node.callee.property.name))
		node = node.callee.object
	return node
}

function scanFile(file) {
	const ast = parseFile(file)
	const result = {
		file,
		requires: new Map(),
		named: new Map(),
		mounts: [],
		localMounts: new Map(),
		routes: [],
		uses: [],
		functions: new Map()
	}
	if (!ast) return result

	// const api = Router().use(a).use(b): calls on that chain belong to "api", not to "Router()"
	const chainOwners = new Map()
	walk(ast, node => {
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && isCallNode(node.init))
			chainOwners.set(chainRootNode(node.init), node.id.name)
	})
	const chainRoot = object => {
		const root = chainRootNode(object)
		return chainOwners.get(root) ?? nameOf(root)
	}

	walk(ast, node => {
		// named handlers: function getBook() {}, const getBook = () => {}, const getBook = catchAsync(() => {})
		if (node.type === "FunctionDeclaration" && node.id) result.functions.set(node.id.name, node)
		if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init) {
			const fn = unwrapHandler(node.init)
			if (isFunctionNode(fn)) result.functions.set(node.id.name, fn)
		}
		// exports.getBook = () => {} and module.exports.getBook = () => {}
		if (node.type === "AssignmentExpression" && isMemberNode(node.left) && /^(module\.)?exports\./.test(nameOf(node.left))) {
			const fn = unwrapHandler(node.right)
			if (isFunctionNode(fn)) result.functions.set(node.left.property.name, fn)
		}

		// const users = require("./users") and const { getUser } = require("./users")
		if (node.type === "VariableDeclarator" && isCallNode(node.init) && node.init.callee.name === "require") {
			const target = resolveModule(file, stringValue(node.init.arguments[0]))
			if (target && node.id.type === "Identifier") result.requires.set(node.id.name, target)
			if (target && node.id.type === "ObjectPattern")
				for (const p of node.id.properties)
					if (p.value?.type === "Identifier") result.named.set(p.value.name, { file: target, name: p.key.name })
		}
		// import users from "./users" and import { getUser } from "./users"
		if (node.type === "ImportDeclaration") {
			const target = resolveModule(file, node.source.value)
			if (!target) return
			for (const s of node.specifiers) {
				if (s.type === "ImportDefaultSpecifier" || s.type === "ImportNamespaceSpecifier") result.requires.set(s.local.name, target)
				if (s.type === "ImportSpecifier") result.named.set(s.local.name, { file: target, name: s.imported.name ?? s.imported.value })
			}
		}

		if (!isCallNode(node) || !isMemberNode(node.callee)) return
		const method = node.callee.property.name
		const owner = chainRoot(node.callee.object)
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
				// app.use(auth) is middleware, app.use(usersRouter) mounts at "", sorted out once every file is read
				const idents = node.arguments.filter(a => a.type === "Identifier").map(a => a.name)
				result.uses.push({ owner, middleware: flattenMiddleware(node.arguments), idents, line })
			}
			return
		}

		if (!METHODS.has(method)) return
		if (routePath !== null && rest.length > 0) {
			result.routes.push(routeEntry(owner, method, routePath, rest, line))
			return
		}
		const chainPath = routeChainPath(node.callee.object)
		if (chainPath !== null && node.arguments.length > 0) result.routes.push(routeEntry(owner, method, chainPath, node.arguments, line))
	})
	return result
}

function routeEntry(owner, method, routePath, args, line) {
	return {
		owner,
		method: method.toUpperCase(),
		path: routePath,
		middleware: flattenMiddleware(args.slice(0, -1)),
		handler: nameOf(args.at(-1)) ?? "?",
		handlerNode: args.at(-1),
		line
	}
}

function joinPath(prefix, routePath) {
	const joined = `${prefix}/${routePath}`.replace(/\/+/g, "/")
	return joined.length > 1 ? joined.replace(/\/$/, "") : joined
}

export function classify(middleware) {
	const enforced = middleware.filter(m => !NOT_ENFORCED.test(m))
	const role = enforced.some(m => ROLE.test(m) || PERMISSION_CALL.test(m))
	const auth = role || enforced.some(m => AUTH.test(m))
	return { auth, role }
}

export function mapRoutes(root) {
	const scans = listSourceFiles(root).map(scanFile)
	const byFile = new Map(scans.map(s => [s.file, s]))
	const isRouterFile = file => byFile.get(file)?.routes.length > 0 || byFile.get(file)?.mounts.length > 0

	// who mounts each file, with what prefix and mount-level middleware
	const mountedBy = new Map()
	const addMount = (target, mount) => {
		if (!mountedBy.has(target)) mountedBy.set(target, [])
		mountedBy.get(target).push(mount)
	}
	for (const scan of scans) {
		for (const mount of scan.mounts) {
			const target = scan.requires.get(mount.target)
			if (target && byFile.has(target)) addMount(target, { parent: scan.file, ...mount })
			// app.use("/api", api) where api is a router built in this file
			else if (mount.target) scan.localMounts.set(mount.target, mount)
		}
		for (const use of scan.uses) {
			const routers = use.idents.filter(id => isRouterFile(scan.requires.get(id)))
			for (const id of routers)
				addMount(scan.requires.get(id), { parent: scan.file, owner: use.owner, prefix: "", middleware: [], line: use.line })
			// a mounted router is not middleware: authController must not count as an auth check
			use.middleware = use.middleware.filter(m => !routers.includes(m))
		}
	}

	// the prefix a router built in this file sits under: api → "/api" when app.use("/api", api)
	function localContext(scan, owner, seen = new Set()) {
		const mount = scan.localMounts.get(owner)
		if (!mount || seen.has(owner)) return { prefix: "", middleware: [] }
		seen.add(owner)
		const outer = localContext(scan, mount.owner, seen)
		return {
			prefix: joinPath(outer.prefix, mount.prefix),
			middleware: [...outer.middleware, ...inheritedUses(scan, mount.owner, mount.line), ...mount.middleware]
		}
	}

	// a file can be mounted at several prefixes, through nested routers
	function contexts(file, seen = new Set()) {
		const parents = mountedBy.get(file)
		if (!parents || seen.has(file)) return [{ prefix: "", middleware: [] }]
		seen.add(file)
		return parents.flatMap(m =>
			contexts(m.parent, new Set(seen)).map(ctx => {
				const local = localContext(byFile.get(m.parent), m.owner)
				return {
					prefix: joinPath(joinPath(ctx.prefix, local.prefix), m.prefix),
					middleware: [
						...ctx.middleware,
						...local.middleware,
						...inheritedUses(byFile.get(m.parent), m.owner, m.line),
						...m.middleware
					]
				}
			})
		)
	}

	// router.use(auth) applies to routes registered after it on the same object
	function inheritedUses(scan, owner, line) {
		return scan.uses.filter(u => u.owner === owner && u.line < line).flatMap(u => u.middleware)
	}

	// the handler's function node and file, following controllers into the files they come from
	function resolveHandler(scan, node) {
		const target = unwrapHandler(node)
		if (isFunctionNode(target)) return { fn: target, file: scan.file }
		if (target?.type === "Identifier") {
			if (scan.functions.has(target.name)) return { fn: scan.functions.get(target.name), file: scan.file }
			const imported = scan.named.get(target.name)
			const fn = byFile.get(imported?.file)?.functions.get(imported.name)
			return fn ? { fn, file: imported.file } : null
		}
		if (isMemberNode(target) && target.object.type === "Identifier") {
			const file = scan.requires.get(target.object.name)
			const fn = byFile.get(file)?.functions.get(target.property.name)
			return fn ? { fn, file } : null
		}
		return null
	}

	const routes = []
	for (const scan of scans) {
		for (const route of scan.routes) {
			const handler = resolveHandler(scan, route.handlerNode)
			for (const ctx of contexts(scan.file)) {
				const local = localContext(scan, route.owner)
				const middleware = [
					...ctx.middleware,
					...local.middleware,
					...inheritedUses(scan, route.owner, route.line),
					...route.middleware
				]
				const entry = {
					method: route.method,
					path: joinPath(joinPath(ctx.prefix, local.prefix), route.path),
					middleware,
					handler: route.handler,
					...classify(middleware),
					file: path.relative(root, scan.file),
					line: route.line
				}
				// kept off JSON output: rules read the handler's AST
				Object.defineProperty(entry, "fn", { value: handler?.fn?.body ? handler.fn : null })
				Object.defineProperty(entry, "fnFile", { value: path.relative(root, handler?.file ?? scan.file) })
				routes.push(entry)
			}
		}
	}
	return routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))
}
