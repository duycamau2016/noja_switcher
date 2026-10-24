import * as vscode from 'vscode'
import * as path from 'path'
import { portManager, vulnManager, TOOLS, ToolMeta } from './managers'
import { describeSource, listWithEffective, resolveTool, setManualPin } from './pinStore'
import { registerCommand, registerDisposable } from './register'
import { worstSeverity, cveIds } from './vulnFormat'
import type { Vulnerability, VulnMap } from '../../src/main/vulnManager'

// ── Versions view ─────────────────────────────────────────────

/** A tool header ("Node", "JDK") or one installed version beneath it. */
type VersionNode =
  | { kind: 'tool'; tool: ToolMeta }
  | {
      kind: 'version'
      tool: ToolMeta
      version: string
      path: string
      /** The version this workspace actually uses. */
      isCurrent: boolean
      /** The version the shared ~/.nodevm/current junction points at. */
      isGlobal: boolean
      external: boolean
      /** Which other tool installed it, when it is not ours. */
      origin?: 'nvm' | 'system'
      /** True when nvm itself currently has this version selected. */
      originActive?: boolean
    }

export class VersionsProvider implements vscode.TreeDataProvider<VersionNode> {
  private readonly _onDidChange = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this._onDidChange.event

  // Security advisories for the installed Node versions. Filled asynchronously
  // (getTreeItem is sync) and keyed by the version set it was scanned for, so a
  // re-render does not re-scan and an install/uninstall does.
  private vulns: VulnMap = {}
  private vulnKey: string | null = null

  refresh() {
    this._onDidChange.fire()
  }

  getChildren(node?: VersionNode): VersionNode[] {
    if (!node) return TOOLS.map((tool) => ({ kind: 'tool', tool }))
    if (node.kind !== 'tool') return []

    // listInstalled() touches the filesystem; a failure here must not blank the
    // whole view.
    let installed: ReturnType<typeof listWithEffective>
    try {
      installed = listWithEffective(node.tool)
    } catch {
      return []
    }

    // Node-only: scan this version set once, then refresh to paint the badges.
    if (node.tool.key === 'node') {
      const versions = installed.map((v) => v.version)
      const key = versions.join('|')
      if (key !== this.vulnKey) {
        this.vulnKey = key
        vulnManager
          .scan(versions)
          .then((map) => {
            this.vulns = map
            this.refresh()
          })
          .catch(() => {})
      }
    }

    return installed.map((v) => ({
      kind: 'version' as const,
      tool: node.tool,
      version: v.version,
      path: v.path,
      isCurrent: v.isCurrent,
      isGlobal: v.isGlobal,
      external: v.external === true,
      origin: v.origin,
      originActive: v.originActive,
    }))
  }

  getTreeItem(node: VersionNode): vscode.TreeItem {
    if (node.kind === 'tool') return this.toolItem(node.tool)
    return this.versionItem(node)
  }

  private toolItem(tool: ToolMeta): vscode.TreeItem {
    const resolved = resolveTool(tool)
    const item = new vscode.TreeItem(tool.noun, vscode.TreeItemCollapsibleState.Expanded)

    item.description = resolved.unresolved
      ? `${resolved.unresolved} — not installed`
      : `${resolved.version ?? 'none'} · ${describeSource(resolved)}`
    item.iconPath = new vscode.ThemeIcon(
      resolved.unresolved ? 'warning' : tool.icon,
      resolved.unresolved ? new vscode.ThemeColor('charts.yellow') : undefined,
    )
    item.tooltip = new vscode.MarkdownString(
      [
        `**${tool.noun}** — ${describeSource(resolved)}`,
        resolved.unresolved
          ? `\`${resolved.unresolved}\` is requested but not installed, so nothing is added to PATH.`
          : resolved.dir ?? '',
        '_A workspace pin affects this VS Code window only._',
      ]
        .filter(Boolean)
        .join('\n\n'),
    )

    const pinned = resolved.source === 'workspace' || resolved.unresolved
    item.contextValue = `nvmTool-${tool.key}-${pinned ? 'pinned' : 'unpinned'}`
    return item
  }

  private versionItem(node: Extract<VersionNode, { kind: 'version' }>): vscode.TreeItem {
    const resolved = resolveTool(node.tool)
    const pinnedHere = node.isCurrent && resolved.source !== 'global'
    const vulns = node.tool.key === 'node' ? this.vulns[node.version] : undefined
    const vulnerable = !!vulns?.length

    const item = new vscode.TreeItem(node.version, vscode.TreeItemCollapsibleState.None)
    item.description = [
      vulnerable ? `⚠️ ${worstSeverity(vulns!)} · ${vulns!.length} CVE` : undefined,
      pinnedHere ? (resolved.source === 'file' ? resolved.file : 'pinned') : undefined,
      node.isGlobal ? 'global' : undefined,
      // "nvm current" already says it is an nvm install — don't print both.
      node.external ? (node.originActive ? 'nvm current' : node.origin ?? 'system') : undefined,
    ]
      .filter(Boolean)
      .join(' · ')

    item.tooltip = new vscode.MarkdownString(
      [
        `**${node.version}**`,
        node.path,
        vulnerable
          ? `⚠️ **${vulns!.length} known security ${vulns!.length === 1 ? 'advisory' : 'advisories'}** (highest: ${worstSeverity(vulns!)})\n\n${cveIds(vulns!)}`
          : '',
        pinnedHere ? `_Pinned for this workspace (${describeSource(resolved)})._` : '',
        node.isGlobal ? '_Also the machine-wide default._' : '',
        node.origin === 'nvm'
          ? `_Installed by nvm${node.originActive ? ', and the version nvm has selected' : ''}. This extension lists it but never modifies it._`
          : node.external
            ? '_Installed outside this extension._'
            : '',
      ]
        .filter(Boolean)
        .join('\n\n'),
    )

    item.iconPath = new vscode.ThemeIcon(
      node.isCurrent ? (pinnedHere ? 'pinned' : 'pass-filled') : node.isGlobal ? 'circle-filled' : 'circle-large-outline',
      node.isCurrent
        ? new vscode.ThemeColor('charts.green')
        : vulnerable
          ? new vscode.ThemeColor('charts.red')
          : undefined,
    )

    // Uninstall is only offered where it can succeed and where it would not rip
    // the ground out from under a pin: the managers refuse to remove the global
    // active version, and external installs are not ours to delete.
    const removable = !node.external && !node.isGlobal && !node.isCurrent
    item.contextValue = [
      'nvmVersion',
      node.isCurrent ? 'active' : 'inactive',
      removable ? 'removable' : 'locked',
    ].join('-')

    if (!node.isCurrent) {
      item.command = {
        command: 'nodeversions.pinVersion',
        title: `Pin ${node.version} to this workspace`,
        arguments: [node],
      }
    }
    return item
  }
}

// ── Install New view ──────────────────────────────────────────

/** A tool header, or one downloadable release beneath it. */
type RemoteNode =
  | { kind: 'tool'; tool: ToolMeta }
  | {
      kind: 'remote'
      tool: ToolMeta
      version: string
      lts: string | false
      date: string
      installed: boolean
      /** Security advisories affecting this release (Node only). */
      vulns?: Vulnerability[]
    }
  | { kind: 'error'; tool: ToolMeta; message: string }

export class InstallProvider implements vscode.TreeDataProvider<RemoteNode> {
  private readonly _onDidChange = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this._onDidChange.event

  /** Remote lists cost a network round-trip, so they are fetched on first
   *  expand and reused until something actually changes them. */
  private cache = new Map<string, RemoteNode[]>()

  refresh() {
    this._onDidChange.fire()
  }

  /** Drop the cached release lists so the next expand re-fetches. */
  invalidate() {
    this.cache.clear()
    this.refresh()
  }

  async getChildren(node?: RemoteNode): Promise<RemoteNode[]> {
    if (!node) return TOOLS.map((tool) => ({ kind: 'tool', tool }))
    if (node.kind !== 'tool') return []

    const cached = this.cache.get(node.tool.key)
    if (cached) return cached

    let children: RemoteNode[]
    try {
      const [remote, installed] = await Promise.all([
        node.tool.vm.listRemote(),
        Promise.resolve(node.tool.vm.listInstalled()),
      ])
      const have = new Set(installed.filter((v) => !v.external).map((v) => v.version))
      const remoteNodes = remote.map((r) => ({
        kind: 'remote' as const,
        tool: node.tool,
        version: r.version,
        lts: r.lts,
        date: r.date,
        installed: have.has(r.version),
        vulns: undefined as Vulnerability[] | undefined,
      }))

      // Node-only: attach advisories so each release can show a CVE badge.
      // Non-fatal — a scan failure just leaves the list unbadged.
      if (node.tool.key === 'node') {
        try {
          const map = await vulnManager.scan(remoteNodes.map((c) => c.version))
          for (const c of remoteNodes) c.vulns = map[c.version]
        } catch {
          // offline / rate-limited: show the list without badges
        }
      }
      children = remoteNodes
    } catch (err: unknown) {
      // Offline or a rate-limited API must show *why*, not an empty list.
      children = [
        {
          kind: 'error',
          tool: node.tool,
          message: String((err as Error)?.message ?? err),
        },
      ]
    }

    this.cache.set(node.tool.key, children)
    return children
  }

  getTreeItem(node: RemoteNode): vscode.TreeItem {
    if (node.kind === 'tool') {
      const item = new vscode.TreeItem(
        node.tool.noun,
        vscode.TreeItemCollapsibleState.Collapsed,
      )
      item.description = `available from ${node.tool.source}`
      item.iconPath = new vscode.ThemeIcon(node.tool.icon)
      item.contextValue = `nvmRemoteTool-${node.tool.key}`
      return item
    }

    if (node.kind === 'error') {
      const item = new vscode.TreeItem(
        `Could not load ${node.tool.noun} releases`,
        vscode.TreeItemCollapsibleState.None,
      )
      item.description = node.message
      item.tooltip = new vscode.MarkdownString(
        [`**${node.tool.source} request failed**`, node.message, '', '_Use the refresh button._'].join(
          '\n\n',
        ),
      )
      item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.yellow'))
      return item
    }

    const item = new vscode.TreeItem(node.version, vscode.TreeItemCollapsibleState.None)
    const vulnerable = !!node.vulns?.length
    const tags = [
      vulnerable ? `⚠️ ${worstSeverity(node.vulns!)} · ${node.vulns!.length} CVE` : undefined,
      node.lts ? `LTS ${node.lts}` : undefined,
      node.date,
    ].filter(Boolean)
    item.description = node.installed ? `installed · ${tags.join(' · ')}` : tags.join(' · ')
    item.tooltip = new vscode.MarkdownString(
      [
        `**${node.version}**`,
        vulnerable
          ? `⚠️ **${node.vulns!.length} known security ${node.vulns!.length === 1 ? 'advisory' : 'advisories'}** (highest: ${worstSeverity(node.vulns!)})\n\n${cveIds(node.vulns!)}`
          : '',
        node.lts ? `LTS: ${node.lts}` : 'Current release (not LTS)',
        `Released: ${node.date || 'unknown'}`,
        '',
        node.installed ? '_Already installed._' : `_Click to download and install from ${node.tool.source}._`,
      ]
        .filter(Boolean)
        .join('\n\n'),
    )
    item.iconPath = new vscode.ThemeIcon(
      node.installed ? 'pass-filled' : 'cloud-download',
      node.installed
        ? new vscode.ThemeColor('charts.green')
        : vulnerable
          ? new vscode.ThemeColor('charts.red')
          : undefined,
    )
    item.contextValue = node.installed ? 'nvmRemote-installed' : 'nvmRemote'

    if (!node.installed) {
      item.command = {
        command: 'nodeversions.installVersion',
        title: `Install ${node.version}`,
        arguments: [node],
      }
    }
    return item
  }
}

// ── Ports view ────────────────────────────────────────────────

interface PortNode {
  port: number
  pid: number
  processName: string
  runtime: string
  address: string
  protocol: string
}

export class PortsProvider implements vscode.TreeDataProvider<PortNode> {
  private readonly _onDidChange = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this._onDidChange.event

  refresh() {
    this._onDidChange.fire()
  }

  async getChildren(node?: PortNode): Promise<PortNode[]> {
    if (node) return []
    try {
      return await portManager.listPorts()
    } catch {
      return []
    }
  }

  getTreeItem(node: PortNode): vscode.TreeItem {
    const item = new vscode.TreeItem(String(node.port), vscode.TreeItemCollapsibleState.None)
    item.description = `${node.processName} · pid ${node.pid}`
    item.tooltip = new vscode.MarkdownString(
      [`**Port ${node.port}**`, `${node.protocol} ${node.address}`, `PID ${node.pid}`].join('\n\n'),
    )
    item.iconPath = new vscode.ThemeIcon(node.runtime === 'java' ? 'coffee' : 'symbol-event')
    item.contextValue = 'nvmPort'
    return item
  }
}

// ── Wiring ────────────────────────────────────────────────────

/**
 * Where a freshly installed release landed. Both managers extract into
 * `<versionsDir>/<version>` using the exact release string, so this mirrors
 * their own destDir computation rather than re-listing the directory.
 */
function remoteInstallPath(node: Extract<RemoteNode, { kind: 'remote' }>): string {
  return path.join(node.tool.vm.versionsDir, node.version)
}

/** Tool headers carry `nvmTool-<key>-…`; recover the tool from the context value. */
function toolFromNode(node: unknown): ToolMeta | null {
  const tool = (node as { tool?: ToolMeta } | undefined)?.tool
  return tool && TOOLS.includes(tool) ? tool : null
}

export function registerTreeViews(context: vscode.ExtensionContext, onChanged: () => void) {
  const versions = new VersionsProvider()
  const install = new InstallProvider()
  const ports = new PortsProvider()

  const refreshAll = () => {
    versions.refresh()
    ports.refresh()
    // Only the "installed" badges change on a switch/uninstall — the release
    // lists themselves are still valid, so this deliberately does not refetch.
    install.refresh()
  }

  registerDisposable(context, () =>
    vscode.window.createTreeView('nodeversions.versions', { treeDataProvider: versions }),
  )
  registerDisposable(context, () =>
    vscode.window.createTreeView('nodeversions.install', { treeDataProvider: install }),
  )
  registerDisposable(context, () =>
    vscode.window.createTreeView('nodeversions.ports', { treeDataProvider: ports }),
  )

  registerCommand(context, 'nodeversions.installVersion', async (node: RemoteNode) => {
    if (!node || node.kind !== 'remote' || node.installed) return

    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Installing ${node.tool.noun} ${node.version}`,
        cancellable: false,
      },
      (progress) => {
        let last = 0
        return node.tool.vm.install(node.version, (p: number) => {
          // withProgress wants an increment, the managers report an absolute
          // percentage — convert, and never report a negative step.
          const step = Math.max(0, p - last)
          last = p
          progress.report({ increment: step, message: `${p}%` })
        })
      },
    )

    if (result.success) {
      // The release list's "installed" badge is now stale for this tool.
      install.invalidate()
      onChanged()
      const use = 'Pin to This Workspace'
      const pick = await vscode.window.showInformationMessage(
        `${node.tool.noun} ${node.version} installed.`,
        use,
      )
      if (pick === use) {
        await vscode.commands.executeCommand('nodeversions.pinVersion', {
          kind: 'version',
          tool: node.tool,
          version: node.version,
          path: remoteInstallPath(node),
          isCurrent: false,
          isGlobal: false,
          external: false,
        })
      }
    } else {
      vscode.window.showErrorMessage(
        result.error ?? `Failed to install ${node.tool.noun} ${node.version}.`,
      )
    }
  })

  registerCommand(context, 'nodeversions.refreshRemote', () => install.invalidate())

  // Pin — the default click action. Scoped to this window; never touches the
  // shared junction, so a second window on another repo is unaffected.
  registerCommand(context, 'nodeversions.pinVersion', async (node: VersionNode) => {
    if (!node || node.kind !== 'version') return
    // Warn before pinning a Node version with known advisories (default click action).
    if (node.tool.key === 'node') {
      const hits = (await vulnManager.scan([node.version]))[node.version]
      if (hits?.length) {
        const proceed = 'Pin anyway'
        const choice = await vscode.window.showWarningMessage(
          `${node.version} has ${hits.length} known security ${hits.length === 1 ? 'advisory' : 'advisories'}.`,
          {
            modal: true,
            detail: `Highest severity: ${worstSeverity(hits)}.\n${cveIds(hits)}\n\nConsider a patched release instead.`,
          },
          proceed,
        )
        if (choice !== proceed) return
      }
    }
    // Record the path, not just the version: the same version string can name
    // both a managed install and an nvm one.
    await setManualPin(node.tool.key, { version: node.version, path: node.path })
    onChanged()
    vscode.window.showInformationMessage(
      `${node.tool.noun} ${node.version} pinned to this workspace. Open a new terminal to pick it up.`,
    )
  })

  registerCommand(context, 'nodeversions.unpinVersion', async (node: unknown) => {
    const tool = toolFromNode(node)
    if (!tool) return
    await setManualPin(tool.key, null)
    onChanged()
    vscode.window.showInformationMessage(
      `${tool.noun} pin removed. This workspace follows the global default again.`,
    )
  })

  // Global switch — kept, but demoted to an explicit context-menu action
  // because it reaches every window and every shell on the machine.
  registerCommand(context, 'nodeversions.setGlobalVersion', async (node: VersionNode) => {
    if (!node || node.kind !== 'version') return
    const proceed = 'Set Global Default'
    const confirm = await vscode.window.showWarningMessage(
      `Make ${node.tool.noun} ${node.version} the global default?`,
      {
        modal: true,
        detail:
          'This repoints the shared link used by every VS Code window, every shell and the desktop app. Workspaces with their own pin are unaffected.',
      },
      proceed,
    )
    if (confirm !== proceed) return

    const result = node.tool.vm.use(node.path)
    if (!result.success) {
      vscode.window.showErrorMessage(result.error ?? `Failed to switch ${node.tool.noun} version.`)
      return
    }
    onChanged()
    vscode.window.showInformationMessage(
      `${node.tool.noun} ${node.version} is now the global default. Open a new terminal to pick it up.`,
    )
  })

  registerCommand(context, 'nodeversions.uninstallVersion', async (node: VersionNode) => {
    if (!node || node.kind !== 'version') return
    const remove = 'Uninstall'
    const confirm = await vscode.window.showWarningMessage(
      `Uninstall ${node.tool.noun} ${node.version}?`,
      { modal: true, detail: `This deletes ${node.path} from disk.` },
      remove,
    )
    if (confirm !== remove) return

    const result = node.tool.vm.uninstall(node.version)
    if (result.success) {
      onChanged()
      vscode.window.showInformationMessage(`${node.tool.noun} ${node.version} uninstalled.`)
    } else {
      vscode.window.showErrorMessage(result.error ?? 'Failed to uninstall.')
    }
  })

  registerCommand(context, 'nodeversions.killPort', async (node: PortNode) => {
    if (!node) return
    const kill = 'Kill Process'
    const confirm = await vscode.window.showWarningMessage(
      `Kill the process on port ${node.port}?`,
      { modal: true, detail: `PID ${node.pid}. Unsaved work in that process is lost.` },
      kill,
    )
    if (confirm !== kill) return

    const result = await portManager.killProcess(node.pid)
    if (result.success) {
      vscode.window.showInformationMessage(`Killed pid ${node.pid}.`)
      ports.refresh()
    } else {
      vscode.window.showErrorMessage(result.error ?? 'Failed to kill the process.')
    }
  })

  registerCommand(context, 'nodeversions.refreshViews', refreshAll)

  return refreshAll
}
