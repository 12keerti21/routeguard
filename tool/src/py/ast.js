// Python source through tree-sitter (WebAssembly), so reading Python needs no Python install
import { readFileSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Parser, Language } from "web-tree-sitter"

export { walk, field, lineOf } from "../go/ast.js"
import { field } from "../go/ast.js"

const GRAMMAR = fileURLToPath(new URL("../../vendor/tree-sitter-python.wasm", import.meta.url))
const SKIP_DIRS = new Set(["node_modules", ".git", "venv", ".venv", "env", "site-packages", "__pycache__", "migrations", "tests", "test", "testing", "docs", "dist", "build", "examples", "example", "fixtures", "e2e"])
const MAX_SOURCE_BYTES = 512 * 1024

let parser = null
export async function initPy() {
	if (parser) return
	await Parser.init()
	parser = new Parser()
	parser.setLanguage(await Language.load(GRAMMAR))
}

export function listPyFiles(root) {
	const files = []
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue
		const full = path.join(root, entry.name)
		if (entry.isDirectory()) files.push(...listPyFiles(full))
		else if (entry.name.endsWith(".py") && !/^(test_.*|.*_test|conftest|setup)\.py$/.test(entry.name) && statSync(full).size <= MAX_SOURCE_BYTES) files.push(full)
	}
	return files
}

export function parsePy(file) {
	try {
		return parser.parse(readFileSync(file, "utf8"))
	} catch {
		return null
	}
}

// 'a', "a", 'a' 'b', f"a" without placeholders; null for anything computed
export function pyString(node, consts) {
	if (!node) return null
	if (node.type === "string") {
		if (node.namedChildren.some(c => c.type === "interpolation")) return null
		return node.namedChildren.filter(c => c.type === "string_content" || c.type === "escape_sequence").map(c => c.text).join("")
	}
	if (node.type === "concatenated_string") {
		const parts = node.namedChildren.map(c => pyString(c, consts))
		return parts.every(p => p !== null) ? parts.join("") : null
	}
	if (node.type === "binary_operator" && field(node, "operator")?.text === "+") {
		const l = pyString(field(node, "left"), consts)
		const r = pyString(field(node, "right"), consts)
		return l !== null && r !== null ? l + r : null
	}
	if (consts && (node.type === "identifier" || node.type === "attribute")) return consts(node.text) ?? null
	return null
}

// request.get_json → "get_json", jsonify → "jsonify"
export function callName(call) {
	const fn = field(call, "function")
	if (!fn) return ""
	if (fn.type === "attribute") return field(fn, "attribute").text
	if (fn.type === "identifier") return fn.text
	return ""
}
export const callObject = call => {
	const fn = field(call, "function")
	return fn?.type === "attribute" ? field(fn, "object") : null
}
export const posArgs = call => (field(call, "arguments")?.namedChildren ?? []).filter(n => n.type !== "keyword_argument" && n.type !== "comment")
export function kwarg(call, name) {
	for (const n of field(call, "arguments")?.namedChildren ?? []) if (n.type === "keyword_argument" && field(n, "name").text === name) return field(n, "value")
	return null
}
export const kwargs = call => (field(call, "arguments")?.namedChildren ?? []).filter(n => n.type === "keyword_argument")

// a function's parameters as [{ name, type, default }]
export function pyParams(fn) {
	const out = []
	for (const p of field(fn, "parameters")?.namedChildren ?? []) {
		if (p.type === "identifier") out.push({ name: p.text, type: "", default: null })
		else if (p.type === "typed_parameter") out.push({ name: p.namedChildren.find(c => c.type === "identifier")?.text, type: field(p, "type")?.text ?? "", default: null })
		else if (p.type === "default_parameter") out.push({ name: field(p, "name").text, type: "", default: field(p, "value") })
		else if (p.type === "typed_default_parameter") out.push({ name: field(p, "name").text, type: field(p, "type")?.text ?? "", default: field(p, "value") })
	}
	return out
}

// list or tuple items as nodes; a single value as one item
export const items = node => (!node ? [] : ["list", "tuple", "set"].includes(node.type) ? node.namedChildren.filter(c => c.type !== "comment") : [node])
