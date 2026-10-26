import type { Vulnerability } from '../types'

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  moderate: 2,
  low: 1,
}

/** Highest severity among a version's CVE advisories, for colour + label. */
export function worstSeverity(vulns: Vulnerability[]): string {
  let worst = 'unknown'
  let rank = -1
  for (const v of vulns) {
    const r = SEVERITY_RANK[v.severity] ?? 0
    if (r > rank) {
      rank = r
      worst = v.severity
    }
  }
  return worst
}

/** Tooltip line for one advisory. */
function line(v: Vulnerability): string {
  const tag = v.kind === 'eol' ? 'END-OF-LIFE' : v.cve.length ? v.cve.join(', ') : 'advisory'
  const summary = v.overview ? ` — ${v.overview}` : ''
  return `[${v.severity.toUpperCase()}] ${tag}${summary}`
}

/**
 * Advisory pills for a Node version. End-of-life and CVE advisories render as
 * separate, visually distinct pills — EOL is ⛔ (violet), CVEs are ⚠️ (red/amber
 * by severity) — so an unsupported runtime reads differently from a patchable one.
 */
export function VulnBadge({ vulns }: { vulns?: Vulnerability[] }) {
  if (!vulns || vulns.length === 0) return null
  const eol = vulns.find((v) => v.kind === 'eol')
  const cves = vulns.filter((v) => v.kind !== 'eol')
  return (
    <>
      {eol && (
        <div className="version-badge eol" title={line(eol)}>
          ⛔ EOL
        </div>
      )}
      {cves.length > 0 && (
        <div className={`version-badge vuln ${worstSeverity(cves)}`} title={cves.map(line).join('\n')}>
          ⚠️ {worstSeverity(cves)} · {cves.length} CVE
        </div>
      )}
    </>
  )
}
