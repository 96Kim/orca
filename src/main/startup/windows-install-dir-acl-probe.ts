import { spawn } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { release } from 'node:os'
import { dirname, join } from 'node:path'
import type { CrashReportBreadcrumbData } from '../../shared/crash-reporting'
import { sanitizeCrashReportString } from '../../shared/crash-reporting'
import { recordCrashBreadcrumb } from '../crash-reporting/crash-breadcrumb-store'
import { recordDurableCrashBreadcrumb } from '../crash-reporting/durable-crash-breadcrumb'
import { whenTracerSinkReady } from '../observability/tracer-sink-ready'
import { readTargetDacl } from './windows-dacl-icacls-reader'
import {
  rollupFields,
  targetFields,
  WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
  type ProbeContext,
  type TargetKey,
  type TargetOutcome
} from './windows-install-dir-acl-breadcrumb-fields'
import { classifyInstallPath } from './windows-install-path-class'

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
 * retained breadcrumb ring that process-gone-recorder already snapshots, plus a
 * span (deferred until the tracer sink exists) that also records healthy
 * launches, without which the poison shape has no base rate to compare against.
 */

export { WINDOWS_INSTALL_DIR_ACL_BREADCRUMB }

/** Whole-probe budget across every icacls call; a diagnostic must never be felt at startup. */
const PROBE_BUDGET_MS = 5_000

/** Electron ships these next to the exe; first hit wins, no globbing. */
const MODULE_SHORTLIST = [
  'ffmpeg.dll',
  'libglesv2.dll',
  'libegl.dll',
  'vk_swiftshader.dll',
  'd3dcompiler_47.dll'
]
const RESOURCE_SHORTLIST = ['icudtl.dat', 'resources.pak', 'chrome_100_percent.pak']

export type WindowsInstallDirAclProbeOptions = {
  /** Test seam — defaults to node:child_process spawn. */
  spawnFn?: typeof spawn
  /** Test seam — defaults to dirname(process.execPath). */
  installDir?: string
  platform?: NodeJS.Platform
  isServeMode?: boolean
  env?: NodeJS.ProcessEnv
  osRelease?: () => string
  /**
   * OS UI language tag, which decides whether icacls prints the well-known
   * package names in the English form the parser can read. Supplied by the
   * caller (electron's `app` is imported there already, and this module must
   * stay require('electron')-free for the plain-Node entry guard); unknown reads
   * as non-English, i.e. verdict unreliable — the conservative direction.
   */
  uiLanguage?: () => string
  gpuFallbackActive?: boolean
  /** Test seam — defaults to PROBE_BUDGET_MS. */
  budgetMs?: number
  /** Test seam — defaults to a non-recursive readdir of the install dir. */
  listInstallDirEntries?: (dir: string) => Promise<string[]>
  recordStartBreadcrumb?: (name: string, data: CrashReportBreadcrumbData) => void
  /** Ring recorder, called as soon as the probe finishes. */
  recordBreadcrumb?: (name: string, data: CrashReportBreadcrumbData) => void
  /** Span-carrying recorder, deferred until `whenTracerSinkReady` resolves. */
  recordDurableBreadcrumb?: (name: string, data: CrashReportBreadcrumbData) => void
  whenTracerSinkReady?: () => Promise<void>
  onDone?: (data: CrashReportBreadcrumbData) => void
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

type Selection = { moduleFile: string | null; resourceFile: string | null; reason?: string }

const NO_SELECTION = (reason: string): Selection => ({
  moduleFile: null,
  resourceFile: null,
  reason
})

/**
 * Why the race: a dead SMB share or stalled removable install root can hang
 * readdir forever, and an unraced listing would mean no breadcrumb at all.
 */
async function selectTargets(
  installDir: string,
  listEntries: (dir: string) => Promise<string[]>,
  deadline: number
): Promise<Selection> {
  const listed = listEntries(installDir).then(
    (entries): Selection => ({
      moduleFile: pickFile(entries, MODULE_SHORTLIST, ['.dll']),
      resourceFile: pickFile(entries, RESOURCE_SHORTLIST, ['.pak', '.dat'])
    }),
    (error: unknown) => NO_SELECTION(`readdir: ${String(error)}`)
  )
  return Promise.race([listed, budgetElapsed(deadline).then(() => NO_SELECTION('readdir-timeout'))])
}

function budgetElapsed(deadline: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, Math.max(deadline - Date.now(), 1))
    timer.unref?.()
  })
}

async function probeTargets(
  options: WindowsInstallDirAclProbeOptions,
  installDir: string,
  deadline: number
): Promise<{ outcomes: [TargetKey, TargetOutcome | null][]; reason?: string }> {
  const spawnFn = options.spawnFn ?? spawn
  // Why start this first: the install dir needs no listing, so a pathological
  // readdir degrades to a partial breadcrumb instead of starving every target.
  const installDirRead = readTargetDacl(spawnFn, installDir, deadline)
  const selection = await selectTargets(
    installDir,
    options.listInstallDirEntries ?? listTopLevelEntries,
    deadline
  )
  const readChild = (name: string | null): Promise<TargetOutcome> | null =>
    name ? readTargetDacl(spawnFn, join(installDir, name), deadline) : null
  const [installDirOutcome, moduleFile, resourceFile] = await Promise.all([
    installDirRead,
    readChild(selection.moduleFile),
    readChild(selection.resourceFile)
  ])
  return {
    outcomes: [
      ['installDir', installDirOutcome],
      ['moduleFile', moduleFile],
      ['resourceFile', resourceFile]
    ],
    reason: selection.reason
  }
}

async function collectProbeData(
  options: WindowsInstallDirAclProbeOptions
): Promise<CrashReportBreadcrumbData> {
  const installDir = options.installDir ?? dirname(process.execPath)
  const deadline = Date.now() + (options.budgetMs ?? PROBE_BUDGET_MS)
  const { outcomes, reason } = await probeTargets(options, installDir, deadline)
  return {
    ...rollupFields(
      outcomes.map(([, outcome]) => outcome),
      { ...probeContext(options, installDir), reason }
    ),
    ...outcomes.reduce<CrashReportBreadcrumbData>(
      (acc, [key, outcome]) => Object.assign(acc, targetFields(key, outcome)),
      {}
    )
  }
}

/**
 * Why two records: the ring must carry the result before a child can die, but
 * the tracer sink is only installed inside app.whenReady, so emitting durably
 * here would drop the span half silently — and with it every healthy-launch
 * report. The retained ring slot is keyed by name, so the later durable record
 * replaces this one rather than costing a second slot.
 */
async function emitProbeResult(
  options: WindowsInstallDirAclProbeOptions,
  data: CrashReportBreadcrumbData
): Promise<void> {
  ;(options.recordBreadcrumb ?? recordCrashBreadcrumb)(WINDOWS_INSTALL_DIR_ACL_BREADCRUMB, data)
  options.onDone?.(data)
  await (options.whenTracerSinkReady ?? whenTracerSinkReady)()
  ;(options.recordDurableBreadcrumb ?? recordDurableCrashBreadcrumb)(
    WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
    data
  )
}

// Why: the failure record replaces the start marker's retained slot, so dropping
// its context would make the worst-case report weaker than the one it overwrites.
function startMarkerFieldsOrEmpty(
  options: WindowsInstallDirAclProbeOptions
): CrashReportBreadcrumbData {
  try {
    return startMarkerFields(
      startMarkerContext(options, options.installDir ?? dirname(process.execPath))
    )
  } catch {
    return {}
  }
}

async function runProbe(options: WindowsInstallDirAclProbeOptions): Promise<void> {
  let data: CrashReportBreadcrumbData
  try {
    data = await collectProbeData(options)
  } catch (error) {
    // Never throw out of a diagnostic; a failed probe still says something.
    data = {
      ...startMarkerFieldsOrEmpty(options),
      status: 'failed',
      reason: sanitizeCrashReportString(`probe: ${String(error)}`, 200)
    }
  }
  await emitProbeResult(options, data)
}

function probeContext(options: WindowsInstallDirAclProbeOptions, installDir: string): ProbeContext {
  return {
    ...startMarkerContext(options, installDir),
    uiLanguage: options.uiLanguage?.() ?? ''
  }
}

type StartMarkerContext = Omit<ProbeContext, 'uiLanguage'>

// Why no uiLanguage: the start marker discards it, and resolving it calls into
// an Electron binding before app.whenReady on the one path that runs
// synchronously at the caller's module scope.
function startMarkerContext(
  options: WindowsInstallDirAclProbeOptions,
  installDir: string
): StartMarkerContext {
  return {
    installPathClass: classifyInstallPath(installDir, options.env ?? process.env),
    windowsBuild: (options.osRelease ?? release)(),
    gpuFallbackActive: options.gpuFallbackActive === true
  }
}

function startMarkerFields(context: StartMarkerContext): CrashReportBreadcrumbData {
  return {
    status: 'started',
    installPathClass: context.installPathClass,
    windowsBuild: sanitizeCrashReportString(context.windowsBuild, 60),
    gpuFallbackActiveThisLaunch: context.gpuFallbackActive
  }
}

// Why: the probe runs once per process; a second call would cost spawns for a
// DACL that cannot meaningfully change mid-process.
let probeStarted = false

export function resetWindowsInstallDirAclProbeForTest(): void {
  probeStarted = false
}

/**
 * Fire-and-forget: returns before any spawn happens and can never delay startup.
 * win32 only; no spawn and no fs I/O on other platforms.
 */
export function probeWindowsInstallDirAcl(options: WindowsInstallDirAclProbeOptions = {}): void {
  if ((options.platform ?? process.platform) !== 'win32' || options.isServeMode === true) {
    return
  }
  if (probeStarted) {
    return
  }
  probeStarted = true
  // Why the try: this runs at the caller's module scope, before app.whenReady,
  // so anything thrown here aborts main-process init and no window is ever
  // created — a diagnostic must never be able to do that. Schedule first so a
  // failing start marker still leaves the probe itself running.
  try {
    // Why setImmediate: even spawning is deferred past the caller, so nothing on
    // the startup path pays for this, not even three CreateProcess calls.
    const deferred = new Promise<void>((resolve) => {
      setImmediate(() => resolve(runProbe(options)))
    })
    void deferred.catch(() => undefined)
    // Why: children can die inside the window before icacls returns, and
    // ProcessGoneDedupe keeps only the first report of a burst. This synchronous
    // marker occupies the same retained slot the result later replaces, so a
    // report taken in that window says "probe in flight" rather than nothing —
    // which is otherwise indistinguishable from an old build or a non-win32 host.
    ;(options.recordStartBreadcrumb ?? recordCrashBreadcrumb)(
      WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
      startMarkerFields(
        startMarkerContext(options, options.installDir ?? dirname(process.execPath))
      )
    )
  } catch {
    // Swallowed deliberately: the recorder itself is the likeliest thrower here,
    // so there is nowhere left to report this that would not throw again.
  }
}
