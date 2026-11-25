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
import { verify } from "../src/verify.js"

const RULES = [bola, bfla, massAssignment, dataExposure, ssrf, rateLimit, businessFlow]

const SEVERITIES = ["LOW", "MEDIUM", "HIGH"]

// process.exit() drops what is still buffered for a pipe, which cut large --json output short
const finish = code => process.stdout.write("", () => process.exit(code))

// routeguard verify <dir> --base-url … --config …: replay the routes against a running app
const verifying = process.argv[2] === "verify"
const args = process.argv.slice(verifying ? 3 : 2)
const VALUE_FLAGS = new Set(["--fail-on", "--base-url", "--config", "--canary-host"])
const option = name => {
	const i = args.indexOf(name)
	return i === -1 ? null : args[i + 1]
}
const json = args.includes("--json")
const sarif = args.includes("--sarif")
// --fail-on HIGH: exit 2 only for findings at or above that severity (default LOW: any finding)
const failOn = (option("--fail-on") ?? "LOW").toUpperCase()
const target = args.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.has(args[i - 1]))

if (!target || !SEVERITIES.includes(failOn) || (verifying && (!option("--base-url") || !option("--config")))) {
	console.error("Usage: routeguard <express-project-dir> [--json | --sarif] [--fail-on LOW|MEDIUM|HIGH]")
	console.error("       routeguard verify <express-project-dir> --base-url <url> --config <file.json> [--allow-writes] [--probe-rate-limits] [--probe-ssrf [--canary-host <host>]] [--json]")
	process.exit(1)
}

const routes = mapRoutes(path.resolve(target))
const other = Object.entries(routes.frameworks).filter(([f]) => f !== "express").sort((a, b) => b[1] - a[1])
if (other.length && other[0][1] > (routes.frameworks.express ?? 0))
	console.error(`warning: this looks like a ${other[0][0]} app (${other[0][1]} files, ${routes.frameworks.express ?? 0} using Express). routeguard reads Express routes only, so these results are unreliable.`)
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

function printReport() {
	const mark = ok => (ok ? "✅" : "❌")
	const rows = routes.map(r => [r.method, r.path, r.middleware.join(", ") || "-", mark(r.auth), mark(r.role), `${r.file}:${r.line}`])
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
}

function printVerification(results) {
	if (results.discovered?.length) {
		console.log("Ids found from the app's own lists:")
		for (const d of results.discovered)
			console.log(`  :${d.param} = ${d.value}  (${d.from}${d.ownerOnly ? ", the owner's only" : ", also visible to the other user"})`)
		console.log("")
	}
	const order = { CONFIRMED: 0, INCONCLUSIVE: 1, PUBLIC: 2, PROTECTED: 3, SKIPPED: 4 }
	const sorted = [...results].filter(r => !r.probe).sort((a, b) => order[a.verdict] - order[b.verdict])
	for (const r of sorted) {
		const codes = r.status ? `owner ${r.status.owner ?? "-"} · other ${r.status.other} · anonymous ${r.status.anonymous}` : ""
		const agreement =
			r.verdict === "CONFIRMED" && r.staticRule ? "static finding confirmed"
			: r.verdict === "CONFIRMED" ? "missed by static analysis"
			: r.verdict === "PROTECTED" && r.staticRule ? `static ${r.staticRule} not reproduced`
			: ""
		console.log(`[${r.verdict}] ${r.route}${codes ? `  (${codes})` : ""}`)
		console.log(`  ${r.reason}${agreement ? ` · ${agreement}` : ""}`)
	}
	const probes = [...results].filter(r => r.probe).sort((a, b) => order[a.verdict] - order[b.verdict])
	if (probes.length) console.log("\nProbes:")
	for (const r of probes) console.log(`[${r.verdict}] ${r.probe}  ${r.route}\n  ${r.reason}`)
	const count = verdict => sorted.filter(r => r.verdict === verdict).length
	console.log(`\n${sorted.length} routes replayed, ${probes.length} probes · ${count("CONFIRMED")} confirmed · ${count("PUBLIC")} public · ${count("PROTECTED")} protected · ${count("INCONCLUSIVE")} inconclusive · ${count("SKIPPED")} skipped`)
}

const exitCode = findings.some(f => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(failOn)) ? 2 : 0

if (verifying) {
	const config = JSON.parse(readFileSync(path.resolve(option("--config")), "utf8"))
	const results = await verify({ routes, findings, baseUrl: option("--base-url"), config,
		allowWrites: args.includes("--allow-writes"),
		probeOptions: {
			rateLimits: args.includes("--probe-rate-limits"),
			ssrf: args.includes("--probe-ssrf"),
			canaryHost: option("--canary-host") ?? config.canaryHost
		}
	})
	if (json) console.log(JSON.stringify(results, null, 2))
	else printVerification(results)
	finish(results.some(r => r.verdict === "CONFIRMED") ? 2 : 0)
} else if (json) {
	console.log(JSON.stringify({ routes, findings }, null, 2))
	finish(exitCode)
} else if (sarif) {
	const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
	console.log(JSON.stringify(toSarif(findings, version), null, 2))
	finish(exitCode)
} else {
	printReport()
	finish(exitCode)
}
