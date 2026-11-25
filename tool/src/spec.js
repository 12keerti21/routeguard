import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"

const SPEC_FILE = /^(openapi|swagger)[\w.-]*\.(json|ya?ml)$/i
const SKIP = new Set(["node_modules", ".git", "dist", "build", "coverage"])

function findSpecs(dir, out = []) {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (SKIP.has(entry.name)) continue
		const full = path.join(dir, entry.name)
		if (entry.isDirectory()) findSpecs(full, out)
		else if (SPEC_FILE.test(entry.name)) out.push(full)
	}
	return out
}

const normalise = p => p.replace(/\{\w+\}/g, ":p").replace(/:(\w+)/g, ":p").replace(/\/$/, "").toLowerCase() || "/"

// the paths an OpenAPI or Swagger file documents, read without a YAML parser:
// JSON through JSON.parse, YAML through the "  /path:" keys under "paths:"
export function listSpecFiles(root) {
	const files = findSpecs(root)
	const paths = new Set()
	let basePath = ""
	for (const file of files) {
		const text = readFileSync(file, "utf8")
		if (file.endsWith(".json")) {
			try {
				const spec = JSON.parse(text)
				Object.keys(spec.paths ?? {}).forEach(p => paths.add(normalise(p)))
				basePath ||= spec.basePath ?? new URL(spec.servers?.[0]?.url ?? "http://x/", "http://x").pathname.replace(/\/$/, "")
			} catch {}
			continue
		}
		const block = text.split(/^paths:\s*$/m)[1]?.split(/^\S/m)[0] ?? ""
		for (const match of block.matchAll(/^ {2}['"]?(\/[^'":\s]*)['"]?:\s*$/gm)) paths.add(normalise(match[1]))
		basePath ||=
			text.match(/^basePath:\s*['"]?(\/\S*?)['"]?\s*$/m)?.[1] ??
			text.match(/^servers:\s*\n\s*-\s*url:\s*['"]?([^'"\s]+)/m)?.[1]?.replace(/^https?:\/\/[^/]+/, "") ??
			""
	}
	return { files, paths, basePath }
}
