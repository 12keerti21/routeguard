// SARIF 2.1.0, the format GitHub code scanning reads
const LEVEL = { HIGH: "error", MEDIUM: "warning", LOW: "note" }
// GitHub ranks alerts by this score: 7.0+ is high, 4.0+ medium
const SCORE = { HIGH: "8.0", MEDIUM: "5.0", LOW: "2.0" }

export function toSarif(findings, version) {
	const rules = [...new Map(findings.map(f => [f.rule, f])).values()].map(f => ({
		id: f.rule,
		name: f.rule,
		shortDescription: { text: f.owasp },
		helpUri: "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
		properties: { tags: ["security", "owasp-api-top-10"] }
	}))

	const results = findings.map(f => {
		const at = f.where.lastIndexOf(":")
		return {
			ruleId: f.rule,
			level: LEVEL[f.severity] ?? "warning",
			message: { text: `${f.route}: ${f.message} Fix: ${f.fix}` },
			locations: [
				{
					physicalLocation: {
						artifactLocation: { uri: f.where.slice(0, at), uriBaseId: "%SRCROOT%" },
						region: { startLine: Number(f.where.slice(at + 1)) }
					}
				}
			],
			// the route identifies a finding even when lines move between commits
			partialFingerprints: { routeguardRoute: `${f.rule}:${f.route}` },
			properties: { "security-severity": SCORE[f.severity] ?? "5.0" }
		}
	})

	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: { driver: { name: "routeguard", version, informationUri: "https://github.com/12keerti21/routeguard", rules } },
				results
			}
		]
	}
}
