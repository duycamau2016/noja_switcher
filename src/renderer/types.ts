// Type declarations for the preload-exposed API
export interface InstalledVersion {
  version: string
  isCurrent: boolean
  path: string
  /** true for installs already on the machine (not managed by this app) — read-only */
  external?: boolean
  /** Where an external install came from. Absent for installs this app manages. */
  origin?: 'nvm' | 'system'
  /** True when the owning tool (nvm) currently has this version selected. */
  originActive?: boolean
}

export interface RemoteVersion {
  version: string
  lts: string | false
  date: string
}

export interface ActionResult {
  success: boolean
  error?: string
}

// ── Security advisories (Node only) ───────────────────────────
export interface Vulnerability {
  cve: string[]
  /** 'critical' | 'high' | 'medium' | 'low' | 'unknown' (lower-cased from the DB). */
  severity: string
  overview?: string
  ref?: string
  /** 'cve' for a security advisory; 'eol' for a synthetic end-of-life notice. */
  kind?: 'cve' | 'eol'
}

/** Keyed by version string (e.g. "v22.13.0"). Safe versions are omitted. */
export type VulnMap = Record<string, Vulnerability[]>

// Common surface shared by the Node and JDK managers — used by the
// generic Install / Installed tabs so they work for either tool.
export interface VmApi {
  listInstalled: () => Promise<InstalledVersion[]>
  listRemote: () => Promise<RemoteVersion[]>
  getCurrent: () => Promise<string | null>
  /** Activate an install by its directory path (works for managed and system/external installs) */
  use: (target: string) => Promise<ActionResult>
  install: (version: string) => Promise<ActionResult>
  uninstall: (version: string) => Promise<ActionResult>
  openInstallDir: () => Promise<void>
  onInstallProgress: (cb: (data: { version: string; progress: number }) => void) => void
  removeInstallProgressListener: () => void
}

export interface NodeApi extends VmApi {
  setupPath: () => Promise<ActionResult>
  checkPath: () => Promise<boolean>
  setupProfile: () => Promise<ActionResult>
  checkProfile: () => Promise<boolean>
  /** Check version strings against the Node.js security DB. Node-only. */
  scanVulnerabilities: (versions: string[]) => Promise<VulnMap>
}

export interface JdkApi extends VmApi {
  setupEnv: () => Promise<ActionResult>
  checkEnv: () => Promise<boolean>
  setupProfile: () => Promise<ActionResult>
  checkProfile: () => Promise<boolean>
}

export interface PlatformApi {
  os: 'win32' | 'darwin' | 'linux'
}

// ── Port monitor ──────────────────────────────────────────────
export interface PortInfo {
  port: number
  pid: number
  processName: string
  runtime: 'node' | 'java'
  address: string
  protocol: 'TCP'
}

export interface PortApi {
  listPorts: () => Promise<PortInfo[]>
  killPort: (pid: number) => Promise<ActionResult>
}

// ── Auto-update ───────────────────────────────────────────────
export interface UpdateApi {
  check: () => Promise<ActionResult>
  install: () => Promise<void>
  getCurrentVersion: () => Promise<string>
  onAvailable: (cb: (version: string) => void) => void
  onNone: (cb: () => void) => void
  onProgress: (cb: (percent: number) => void) => void
  onDownloaded: (cb: (version: string) => void) => void
  onError: (cb: (message: string) => void) => void
  removeListeners: () => void
}

declare global {
  interface Window {
    nodevm: NodeApi
    jdkvm: JdkApi
    portvm: PortApi
    updatevm: UpdateApi
    platform: PlatformApi
    /**
     * Set to 'vscode' by the VS Code extension's webview bridge; undefined in
     * Electron. Used to hide the self-update UI, which the Marketplace owns.
     * See extension/webview/bridge.ts.
     */
    __NVM_HOST__?: 'vscode'
  }
}
