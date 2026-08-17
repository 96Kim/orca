import { spawn } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { release } from 'node:os'
import { dirname, join } from 'node:path'
import type { CrashReportBreadcrumbData } from '../../shared/crash-reporting'
import { sanitizeCrashReportString } from '../../shared/crash-reporting'
import { recordDurableCrashBreadcrumb } from '../crash-reporting/durable-crash-breadcrumb'
import { getIcaclsExePath } from '../win32-utils'
import {
  mergePackageAuthorityAceFacts,
  parsePackageAuthorityAces,
  type PackageAuthorityAceFacts
} from './windows-package-authority-aces'

/**
 * Read-only DACL probe of the win32 install directory.
 *
 * Why: six Windows 11 26200 crash reports show GPU + renderer both dying at
 * init with STATUS_BREAKPOINT before any Orca JS runs, which on its own says
 * only "a child asserted". A lab repro on stock Electron 43.1.0 turned that
 * signature on and off deterministically by adding an unresolvable
 * S-1-15-2-* ACE to the install tree with neither S-1-15-2-1 nor S-1-15-2-2
 * present. We have no evidence a crashing machine is in that state — this
 * breadcrumb is how we find out, riding along with the next such crash via the
 * retained breadcrumb ring that process-gone-recorder already snapshots.
 *
 * Read-only by construction: the only argv ever passed to icacls is the target
 * path. No /grant, /deny, /reset, /setowner — and never /T, because a recursive
 * walk on a real profile measured 62s (see windows-user-data-acl.ts).
 */

export const WINDOWS_INSTALL_DIR_ACL_BREADCRUMB = 'windows_install_dir_acl'

/** Whole-probe budget; a diagnostic must never be felt at startup. */
const PROBE_BUDGET_MS = 5_000
// Why: an unresolved S-1-15-2-<hash> derives from a package moniker, so it hints
// at installed software. Correlating the same SID across reports is exactly what
// identifies the polluting tool, which is the diagnostic value — so keep the raw
// form but cap the count and sanitize it.
const MAX_REPORTED_SIDS = 3

/** Electron ships these next to the exe; first hit wins, no globbing. */
const MODULE_SHORTLIST = [
  'ffmpeg.dll',
  'libglesv2.dll',
  'libegl.dll',
  'vk_swiftshader.dll',
  'd3dcompiler_47.dll'
]
const RESOURCE_SHORTLIST = ['icudtl.dat', 'resources.pak', 'chrome_100_percent.pak']

export type InstallPathClass =
  | 'localappdata-programs'
  | 'program-files'
  | 'program-files-x86'
  | 'appdata-roaming'
  | 'other'

type TargetKey = 'installDir' | 'moduleFile' | 'resourceFile'

type TargetOutcome = { facts: PackageAuthorityAceFacts } | { reason: string }

export type WindowsInstallDirAclProbeOptions = {
  /** Test seam — defaults to node:child_process spawn. */
  spawnFn?: typeof spawn
  /** Test seam — defaults to dirname(process.execPath). */
  installDir?: string
  platform?: NodeJS.Platform
  isServeMode?: boolean
  env?: NodeJS.ProcessEnv
  osRelease?: () => string
  gpuFallbackActive?: boolean
  /** Test seam — defaults to a non-recursive readdir of the install dir. */
  listInstallDirEntries?: (dir: string) => Promise<string[]>
  recordBreadcrumb?: (name: string, data: CrashReportBreadcrumbData) => void
  onDone?: (data: CrashReportBreadcrumbData) => void
}

function normalizeDir(value: string | undefined): string | null {
  const trimmed = value?.trim()
  return trimmed
    ? trimmed
        .replace(/[\\/]+$/, '')
        .replace(/\//g, '\\')
        .toLowerCase()
    : null
}

export function classifyInstallPath(
  installDir: string,
  env: NodeJS.ProcessEnv = process.env
): InstallPathClass {
  const target = normalizeDir(installDir)
  if (!target) {
    return 'other'
  }
  const localAppData = normalizeDir(env.LOCALAPPDATA)
  const candidates: [string | null, InstallPathClass][] = [
    [localAppData ? `${localAppData}\\programs` : null, 'localappdata-programs'],
    [normalizeDir(env['ProgramFiles(x86)']), 'program-files-x86'],
    [normalizeDir(env.ProgramW6432 ?? env.ProgramFiles), 'program-files'],
    [normalizeDir(env.APPDATA), 'appdata-roaming']
  ]
  for (const [root, klass] of candidates) {
    if (root && (target === root || target.startsWith(`${root}\\`))) {
      return klass
    }
  }
  return 'other'
}

function pickFile(entries: string[], shortlist: string[], extensions: string[]): string | null {
  const byLowerName = new Map(entries.map((entry) => [entry.toLowerCase(), entry]))
  for (const name of shortlist) {
    const hit = byLowerName.get(name)
    if (hit) {
      return hit
    }
  }
  return (
    entries.find((entry) => extensions.some((ext) => entry.toLowerCase().endsWith(ext))) ?? null
  )
}

async function listTopLevelEntries(dir: string): Promise<string[]> {
  // Why: top level only, withFileTypes so a subdirectory is never mistaken for
  // a content file. Never recursive — that is the 62s lesson.
  const entries = await readdir(dir, { withFileTypes: true })
  return entries.filter((entry) => entry.isFile()).map((entry) => entry.name)
}

function runIcacls(
  spawnFn: typeof spawn,
  target: string,
  timeoutMs: number
): Promise<{ stdout: string } | { reason: string }> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>
    try {
      // The entire argv: one path, zero flags. Read-only, non-recursive.
      child = spawnFn(getIcaclsExePath(), [target], {
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true
      })
    } catch (error) {
      resolve({ reason: `spawn: ${String(error)}` })
      return
    }
    let stdout = ''
    let settled = false
    const settle = (result: { stdout: string } | { reason: string }): void => {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    const timer = setTimeout(
      () => {
        child.kill()
        settle({ reason: 'timeout' })
      },
      Math.max(timeoutMs, 1)
    )
    timer.unref?.()
    child.stdout?.setEncoding('utf-8')
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk
    })
    child.on('error', (error) => settle({ reason: `spawn: ${error.message}` }))
    // Why 'close' not 'exit': 'exit' can fire before stdout has been drained,
    // which would silently parse an empty DACL as a clean one.
    child.on('close', (code) =>
      settle(code === 0 ? { stdout } : { reason: `exit ${String(code)}` })
    )
  })
}

async function probeTarget(
  spawnFn: typeof spawn,
  target: string,
  deadline: number
): Promise<TargetOutcome> {
  const remaining = deadline - Date.now()
  if (remaining <= 0) {
    return { reason: 'budget-exhausted' }
  }
  const result = await runIcacls(spawnFn, target, remaining)
  if ('reason' in result) {
    return result
  }
  return { facts: parsePackageAuthorityAces(result.stdout, target) }
}

function targetFields(key: TargetKey, outcome: TargetOutcome | null): CrashReportBreadcrumbData {
  if (!outcome) {
    return { [`${key}Reason`]: 'not-found' }
  }
  if ('reason' in outcome) {
    return { [`${key}Reason`]: sanitizeCrashReportString(outcome.reason, 200) }
  }
  const { facts } = outcome
  return {
    [`${key}PackageAceCount`]: facts.packageAceCount,
    [`${key}UnresolvedPackageSidCount`]: facts.unresolvedPackageSidCount,
    [`${key}CapabilitySidCount`]: facts.capabilitySidCount,
    [`${key}InheritedPackageAceCount`]: facts.inheritedPackageAceCount,
    [`${key}HasAllApplicationPackages`]: facts.hasAllApplicationPackages,
    [`${key}HasAllRestrictedAppPackages`]: facts.hasAllRestrictedAppPackages,
    [`${key}MatchesPoisonSignature`]: facts.matchesPoisonSignature
  }
}

function rollupFields(
  outcomes: (TargetOutcome | null)[],
  context: { installPathClass: InstallPathClass; windowsBuild: string; gpuFallback: boolean }
): CrashReportBreadcrumbData {
  const facts = mergePackageAuthorityAceFacts(
    outcomes.flatMap((outcome) => (outcome && 'facts' in outcome ? [outcome.facts] : []))
  )
  return {
    probedTargetCount: outcomes.filter((outcome) => outcome && 'facts' in outcome).length,
    packageAceCount: facts.packageAceCount,
    hasAllApplicationPackages: facts.hasAllApplicationPackages,
    hasAllRestrictedAppPackages: facts.hasAllRestrictedAppPackages,
    unresolvedPackageSidCount: facts.unresolvedPackageSidCount,
    unresolvedPackageSids: sanitizeCrashReportString(
      facts.unresolvedPackageSids.slice(0, MAX_REPORTED_SIDS).join(' '),
      400
    ),
    capabilitySidCount: facts.capabilitySidCount,
    inheritedPackageAceCount: facts.inheritedPackageAceCount,
    explicitPackageAceCount: facts.explicitPackageAceCount,
    friendlyNameFallbackUsed: facts.friendlyNameFallbackUsed,
    matchesPoisonSignature: facts.matchesPoisonSignature,
    installPathClass: context.installPathClass,
    windowsBuild: sanitizeCrashReportString(context.windowsBuild, 60),
    // Why: an already-fallen-back launch has no GPU child at all, which changes
    // what the absence of a GPU crash means in a field report.
    gpuFallbackActiveThisLaunch: context.gpuFallback
  }
}

async function selectTargets(
  installDir: string,
  listEntries: (dir: string) => Promise<string[]>
): Promise<{ moduleFile: string | null; resourceFile: string | null; reason?: string }> {
  try {
    const entries = await listEntries(installDir)
    return {
      moduleFile: pickFile(entries, MODULE_SHORTLIST, ['.dll']),
      resourceFile: pickFile(entries, RESOURCE_SHORTLIST, ['.pak', '.dat'])
    }
  } catch (error) {
    return { moduleFile: null, resourceFile: null, reason: `readdir: ${String(error)}` }
  }
}

async function runProbe(options: WindowsInstallDirAclProbeOptions): Promise<void> {
  const env = options.env ?? process.env
  const installDir = options.installDir ?? dirname(process.execPath)
  const spawnFn = options.spawnFn ?? spawn
  const listEntries = options.listInstallDirEntries ?? listTopLevelEntries
  const deadline = Date.now() + PROBE_BUDGET_MS
  const selection = await selectTargets(installDir, listEntries)
  const outcomes: [TargetKey, TargetOutcome | null][] = [
    ['installDir', await probeTarget(spawnFn, installDir, deadline)],
    [
      'moduleFile',
      selection.moduleFile
        ? await probeTarget(spawnFn, join(installDir, selection.moduleFile), deadline)
        : null
    ],
    [
      'resourceFile',
      selection.resourceFile
        ? await probeTarget(spawnFn, join(installDir, selection.resourceFile), deadline)
        : null
    ]
  ]
  const data: CrashReportBreadcrumbData = {
    ...rollupFields(
      outcomes.map(([, outcome]) => outcome),
      {
        installPathClass: classifyInstallPath(installDir, env),
        windowsBuild: (options.osRelease ?? release)(),
        gpuFallback: options.gpuFallbackActive === true
      }
    ),
    ...outcomes.reduce<CrashReportBreadcrumbData>(
      (acc, [key, outcome]) => Object.assign(acc, targetFields(key, outcome)),
      {}
    )
  }
  if (selection.reason) {
    data.reason = sanitizeCrashReportString(selection.reason, 200)
  }
  ;(options.recordBreadcrumb ?? recordDurableCrashBreadcrumb)(
    WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
    data
  )
  options.onDone?.(data)
}

// Why: openMainWindow runs again on dock/tray re-activation, and the install
// tree's DACL cannot change mid-process in a way worth a second breadcrumb.
let probeStarted = false

export function resetWindowsInstallDirAclProbeForTest(): void {
  probeStarted = false
}

/**
 * Fire-and-forget: returns before any spawn happens and can never delay window
 * creation. win32 only; no spawn and no fs I/O on other platforms.
 */
export function probeWindowsInstallDirAcl(options: WindowsInstallDirAclProbeOptions = {}): void {
  if ((options.platform ?? process.platform) !== 'win32' || options.isServeMode === true) {
    return
  }
  if (probeStarted) {
    return
  }
  probeStarted = true
  void runProbe(options).catch((error: unknown) => {
    // Never throw out of a diagnostic; a failed probe still says something.
    ;(options.recordBreadcrumb ?? recordDurableCrashBreadcrumb)(
      WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
      { reason: sanitizeCrashReportString(`probe: ${String(error)}`, 200) }
    )
    options.onDone?.({ reason: 'probe-error' })
  })
}
