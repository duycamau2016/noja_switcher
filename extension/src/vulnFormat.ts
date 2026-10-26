// Shared formatting for security-advisory display in the extension host
// (tree views + panel modals). The React renderer has its own copy in
// src/renderer/components/VulnBadge.tsx — it is a separate build and cannot
// import from here.

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, moderate: 2, low: 1 }

/** Highest severity label among a version's advisories. */
export function worstSeverity(vulns: { severity: string }[]): string {
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

/** Comma-joined CVE ids, capped so a long list stays readable. */
export function cveIds(vulns: { cve: string[] }[], max = 6): string {
  const ids = vulns.flatMap((v) => v.cve).filter(Boolean)
  const shown = ids.slice(0, max).join(', ')
  return ids.length > max ? `${shown}, +${ids.length - max} more` : shown || 'known issues'
}

/** Short label, e.g. "EOL", "high · 3 CVE", or "EOL · high · 3 CVE". */
export function summarize(vulns: { kind?: string; severity: string; cve: string[] }[]): string {
  const eol = vulns.some((v) => v.kind === 'eol')
  const cves = vulns.filter((v) => v.kind !== 'eol')
  const parts: string[] = []
  if (eol) parts.push('EOL')
  if (cves.length) parts.push(`${worstSeverity(cves)} · ${cves.length} CVE`)
  return parts.join(' · ') || 'advisory'
}

/** The end-of-life overview text if the version is EOL, else ''. */
export function eolNote(vulns: { kind?: string; overview?: string }[]): string {
  return vulns.find((v) => v.kind === 'eol')?.overview ?? ''
}

/** Tree-row text with distinct markers per kind: "⛔ EOL · ⚠️ high · 3 CVE". */
export function badgeText(vulns: { kind?: string; severity: string; cve: string[] }[]): string {
  const eol = vulns.some((v) => v.kind === 'eol')
  const cves = vulns.filter((v) => v.kind !== 'eol')
  const parts: string[] = []
  if (eol) parts.push('⛔ EOL')
  if (cves.length) parts.push(`⚠️ ${worstSeverity(cves)} · ${cves.length} CVE`)
  return parts.join(' · ')
}

/** True when any entry is an end-of-life notice. */
export function hasEol(vulns: { kind?: string }[]): boolean {
  return vulns.some((v) => v.kind === 'eol')
}
