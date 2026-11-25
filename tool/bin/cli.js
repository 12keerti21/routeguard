#!/usr/bin/env node
import path from "node:path"
import { mapRoutes } from "../src/mapper.js"
import { bola } from "../src/rules/bola.js"

const RULES = [bola]

const args = process.argv.slice(2)
const json = args.includes("--json")
const target = args.find(a => !a.startsWith("--"))

if (!target) {
	console.error("Usage: routeguard <express-project-dir> [--json]")
	process.exit(1)
}

const routes = mapRoutes(path.resolve(target))
const findings = routes.flatMap(r => RULES.map(rule => rule(r)).filter(Boolean))

if (json) {
	console.log(JSON.stringify({ routes, findings }, null, 2))
	process.exit(findings.length ? 2 : 0)
}

const mark = ok => (ok ? "✅" : "❌")
const rows = routes.map(r => [
	r.method,
	r.path,
	r.middleware.join(", ") || "-",
	mark(r.auth),
	mark(r.role),
	`${r.file}:${r.line}`
])
const header = ["METHOD", "PATH", "MIDDLEWARE", "AUTH", "ROLE", "WHERE"]
const widths = header.map((h, i) => Math.max(h.length, ...rows.map(r => r[i].length)))
const line = cells => cells.map((c, i) => c.padEnd(widths[i])).join("  ")

console.log(line(header))
console.log(widths.map(w => "-".repeat(w)).join("  "))
rows.forEach(r => console.log(line(r)))

const noAuth = routes.filter(r => !r.auth).length
console.log(`\n${routes.length} routes · ${noAuth} without an auth check · ${routes.filter(r => !r.role).length} without a role check`)

console.log(`\nFINDINGS (${findings.length})\n`)
for (const f of findings) {
	console.log(`[${f.severity}] ${f.rule}  ${f.route}  (${f.where})`)
	console.log(`  ${f.owasp}`)
	console.log(`  ${f.message}`)
	console.log(`  Fix: ${f.fix}\n`)
}
process.exit(findings.length ? 2 : 0)
