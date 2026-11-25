#!/usr/bin/env node
import { readFileSync } from "node:fs"
import path from "node:path"
import { mapRoutes } from "../src/mapper.js"
import { toSarif } from "../src/sarif.js"
import { bola } from "../src/rules/bola.js"
import { bfla } from "../src/rules/bfla.js"
import { massAssignment } from "../src/rules/massAssignment.js"
import { ssrf } from "../src/rules/ssrf.js"
import { rateLimit } from "../src/rules/rateLimit.js"
import { dataExposure } from "../src/rules/dataExposure.js"
import { misconfig } from "../src/rules/misconfig.js"
import { inventory } from "../src/rules/inventory.js"
import { businessFlow } from "../src/rules/businessFlow.js"
import { consumption } from "../src/rules/consumption.js"

const RULES = [bola, bfla, massAssignment, dataExposure, ssrf, rateLimit, businessFlow]

const SEVERITIES = ["LOW", "MEDIUM", "HIGH"]

const args = process.argv.slice(2)
const option = name => {
	const i = args.indexOf(name)
	return i === -1 ? null : args[i + 1]
}
const json = args.includes("--json")
const sarif = args.includes("--sarif")
// --fail-on HIGH: exit 2 only for findings at or above that severity (default LOW: any finding)
const failOn = (option("--fail-on") ?? "LOW").toUpperCase()
const target = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--fail-on")

if (!target || !SEVERITIES.includes(failOn)) {
	console.error("Usage: routeguard <express-project-dir> [--json | --sarif] [--fail-on LOW|MEDIUM|HIGH]")
	process.exit(1)
}

const routes = mapRoutes(path.resolve(target))
const suppressed = (route, finding) => route.ignored === "all" || route.ignored?.has(finding.rule)
// a router mounted twice reports the same code twice
const seen = new Set()
const root = path.resolve(target)
const findings = [
	...routes.flatMap(r => RULES.map(rule => rule(r)).filter(f => f && !suppressed(r, f))),
	// checks that look at the app as a whole, not one route
	...inventory(routes, root),
	...misconfig(root),
	...consumption(root)
].filter(f => !seen.has(`${f.rule} ${f.route} ${f.where}`) && seen.add(`${f.rule} ${f.route} ${f.where}`))

const exitCode = findings.some(f => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(failOn)) ? 2 : 0

if (json) {
	console.log(JSON.stringify({ routes, findings }, null, 2))
	process.exit(exitCode)
}

if (sarif) {
	const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
	console.log(JSON.stringify(toSarif(findings, version), null, 2))
	process.exit(exitCode)
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
process.exit(exitCode)
