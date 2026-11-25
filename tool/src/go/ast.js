// Go source through tree-sitter (WebAssembly), so reading Go needs no Go toolchain
import { readFileSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Parser, Language } from "web-tree-sitter"

const GRAMMAR = fileURLToPath(new URL("../../vendor/tree-sitter-go.wasm", import.meta.url))
const SKIP_DIRS = new Set(["vendor", "testdata", "node_modules", ".git", "third_party", "mocks", "mock", "e2e", "examples", "example"])
const MAX_SOURCE_BYTES = 512 * 1024

let parser = null
export async function initGo() {
	if (parser) return
	await Parser.init()
	parser = new Parser()
	parser.setLanguage(await Language.load(GRAMMAR))
}

export function listGoFiles(root) {
	const files = []
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue
		const full = path.join(root, entry.name)
		if (entry.isDirectory()) files.push(...listGoFiles(full))
		else if (entry.name.endsWith(".go") && !entry.name.endsWith("_test.go") && statSync(full).size <= MAX_SOURCE_BYTES) files.push(full)
	}
	return files
}

export function parseGo(file) {
	try {
		const source = readFileSync(file, "utf8")
		return { tree: parser.parse(source), source }
	} catch {
		return null
	}
}

export function walk(node, visit) {
	if (!node) return
	if (visit(node) === false) return
	for (const child of node.namedChildren) walk(child, visit)
}

export const field = (node, name) => node?.childForFieldName(name) ?? null
export const lineOf = node => node.startPosition.row + 1

// "a", `a` and "a" + "b"; null for anything computed
export function stringValue(node, consts = { get: () => undefined }) {
	if (!node) return null
	if (node.type === "interpreted_string_literal" || node.type === "raw_string_literal") return node.text.slice(1, -1)
	if (node.type === "identifier") return consts.get(node.text) ?? null
	if (node.type === "selector_expression") return consts.get(field(node, "field").text) ?? null
	if (node.type === "binary_expression" && field(node, "operator")?.text === "+") {
		const left = stringValue(field(node, "left"), consts)
		const right = stringValue(field(node, "right"), consts)
		return left !== null && right !== null ? left + right : null
	}
	if (node.type === "parenthesized_expression") return stringValue(node.namedChildren[0], consts)
	return null
}

// c.JSON → "JSON", chi.URLParam → "URLParam", handler → "handler"
export function calleeName(call) {
	const fn = field(call, "function")
	if (!fn) return ""
	if (fn.type === "selector_expression") return field(fn, "field").text
	if (fn.type === "identifier") return fn.text
	if (fn.type === "generic_type" || fn.type === "index_expression") return fn.namedChildren[0]?.text ?? ""
	return ""
}

// the text before the last dot: c.JSON → "c", db.Where(...).First → "db.Where(...)"
export function calleeObject(call) {
	const fn = field(call, "function")
	return fn?.type === "selector_expression" ? field(fn, "operand") : null
}

export const args = call => field(call, "arguments")?.namedChildren.filter(n => n.type !== "comment") ?? []

// identifiers inside an expression
export function identifiers(node) {
	const names = new Set()
	walk(node, n => {
		if (n.type === "identifier") names.add(n.text)
		if (n.type === "func_literal") return false
	})
	return names
}

// a function's parameters as [{ name, type }]
export function paramsOf(fn) {
	const list = field(fn, "parameters")
	const out = []
	for (const decl of list?.namedChildren ?? []) {
		if (decl.type !== "parameter_declaration" && decl.type !== "variadic_parameter_declaration") continue
		const type = field(decl, "type")?.text ?? ""
		const names = decl.namedChildren.filter(c => c.type === "identifier")
		if (names.length === 0) out.push({ name: null, type })
		for (const n of names) out.push({ name: n.text, type })
	}
	return out
}

// the type names a function returns, in order: (*User, error) → ["User", "error"]
export function resultsOf(fn) {
	const result = field(fn, "result")
	if (!result) return []
	const types = result.type === "parameter_list" ? result.namedChildren.map(d => field(d, "type") ?? d) : [result]
	return types.map(t => qualType(t?.text ?? ""))
}

// *models.User, []models.User → "models.User": the package stays, so the right User is found
export const qualType = text => text.replace(/^[\[\]*&\s]+/, "").replace(/[\[\]*]/g, "")

// *models.User, []User, []*User → "User"
export const baseType = text => text.replace(/^[\[\]*&\s]+/, "").replace(/^\w+\./, "").replace(/[\[\]*]/g, "")
