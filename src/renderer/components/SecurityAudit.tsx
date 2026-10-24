import { useState } from 'react'
import type { Vulnerability } from '../types'
import { VulnBadge } from './VulnBadge'

interface AuditResult {
  total: number
  flagged: { version: string; vulns: Vulnerability[] }[]
}

/** On-demand "audit" — scans every installed Node version against the security DB.
 *  Node-only; rendered inside SettingsTab (which App shows only for the Node tool). */
export function SecurityAudit() {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AuditResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      const installed = await window.nodevm.listInstalled()
      const map = await window.nodevm.scanVulnerabilities(installed.map((v) => v.version))
      const flagged = installed
        .map((v) => ({ version: v.version, vulns: map[v.version] }))
        .filter((x): x is { version: string; vulns: Vulnerability[] } => !!x.vulns?.length)
      setResult({ total: installed.length, flagged })
    } catch {
      setError('Could not reach the security database. Check your connection and try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="path-hint">
      <strong style={{ color: 'var(--text)' }}>Security audit</strong>
      <br />
      <br />
      <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>
        Check every installed Node version against the official Node.js security database
        (cached locally, refreshed daily).
      </p>
      <button className="btn btn-primary" disabled={busy} onClick={run}>
        {busy ? 'Scanning…' : 'Scan installed versions'}
      </button>

      {error && (
        <p style={{ color: 'var(--danger)', fontSize: '12px', marginTop: '12px' }}>{error}</p>
      )}

      {result && !error && (
        <div style={{ marginTop: '12px' }}>
          {result.flagged.length === 0 ? (
            <span style={{ color: 'var(--accent)' }}>
              ✓ No known advisories across {result.total} installed version
              {result.total === 1 ? '' : 's'}.
            </span>
          ) : (
            <>
              <p style={{ color: 'var(--danger)', fontSize: '13px', marginBottom: '8px' }}>
                {result.flagged.length} of {result.total} installed version
                {result.total === 1 ? '' : 's'} affected:
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {result.flagged.map((f) => (
                  <div key={f.version} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>{f.version}</span>
                    <VulnBadge vulns={f.vulns} />
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
