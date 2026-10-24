import type { Vulnerability } from '../types'

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  moderate: 2,
  low: 1,
}

/** Highest severity among a version's advisories, for colour + label. */
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

/** Human-readable tooltip: one line per advisory with its CVEs and summary. */
function tooltip(vulns: Vulnerability[]): string {
  return vulns
    .map((v) => {
      const ids = v.cve.length ? v.cve.join(', ') : 'advisory'
      const sev = v.severity.toUpperCase()
      const summary = v.overview ? ` — ${v.overview}` : ''
      return `[${sev}] ${ids}${summary}`
    })
    .join('\n')
}

/** Red ⚠️ pill shown next to a Node version with known security advisories. */
export function VulnBadge({ vulns }: { vulns?: Vulnerability[] }) {
  if (!vulns || vulns.length === 0) return null
  const worst = worstSeverity(vulns)
  const label = vulns.length === 1 ? '1 advisory' : `${vulns.length} advisories`
  return (
    <div className={`version-badge vuln ${worst}`} title={tooltip(vulns)}>
      ⚠️ {worst} · {label}
    </div>
  )
}
