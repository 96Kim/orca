import { EventEmitter } from 'node:events'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  sanitizeCrashReportDetails,
  type CrashReportBreadcrumbData
} from '../../shared/crash-reporting'
import {
  probeWindowsInstallDirAcl,
  resetWindowsInstallDirAclProbeForTest,
  WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
  type WindowsInstallDirAclProbeOptions
} from './windows-install-dir-acl-probe'
import { classifyInstallPath } from './windows-install-path-class'
import { parsePackageAuthorityAces } from './windows-package-authority-aces'

const INSTALL_DIR = 'C:\\Users\\neil\\AppData\\Local\\Programs\\orca'
const ENTRIES = ['orca.exe', 'ffmpeg.dll', 'icudtl.dat', 'LICENSE.txt']

// Verbatim icacls output shapes captured on Windows 11 build 26200.
const CLEAN = (target: string): string =>
  `${target} NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\\Administrators:(I)(OI)(CI)(F)
                    awin\\neil:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

const ORPHAN = (target: string): string =>
  `${target} S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\\Administrators:(I)(OI)(CI)(F)
                    awin\\neil:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

const ORPHAN_PLUS_RESTRICTED = (target: string): string =>
  `${target} APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\\Administrators:(I)(OI)(CI)(F)
                    awin\\neil:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

const ORPHAN_PLUS_ALL_APP_PACKAGES = (target: string): string =>
  `${target} APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

// A deny ACE for the well-known principal grants nothing, so the orphan is
// still unsatisfied — the shape a hardening policy or an EDR agent leaves.
const ORPHAN_PLUS_DENIED_ALL_APP_PACKAGES = (target: string): string =>
  `${target} APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(DENY)(OI)(CI)(F)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

// Inherit-only: applies to children, never to this object, so it cannot
// satisfy an orphan on the object the way the repro's (OI)(CI)(RX) grant did.
const ORPHAN_PLUS_INHERIT_ONLY_RESTRICTED = (target: string): string =>
  `${target} APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

const CAPABILITY_ONLY = (target: string): string =>
  `${target} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                    BUILTIN\\Administrators:(OI)(CI)(F)
                    awin\\neil:(OI)(CI)(F)
                    S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575:(S,X)

Successfully processed 1 files; Failed processing 0 files
`

// German-shaped icacls output: every principal, including the well-known
// package grant, is localized so no name regex can fire.
const LOCALIZED_ORPHAN_PLUS_GRANT = (target: string): string =>
  `${target} ANWENDUNGSPAKETAUTORITÄT\\ALLE ANWENDUNGSPAKETE:(OI)(CI)(RX)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    NT-AUTORITÄT\\SYSTEM:(I)(OI)(CI)(F)
                    VORDEFINIERT\\Administratoren:(I)(OI)(CI)(F)

Erfolgreich verarbeitete Dateien: 1; bei 0 Dateien ist ein Verarbeitungsfehler aufgetreten.
`

// French-shaped icacls output: BUILTIN and NT AUTHORITY survive verbatim (as they
// do on Spanish, Portuguese and Japanese Windows) while the package grant is
// localized — so principal spelling cannot vouch for the package names.
const PARTLY_LOCALIZED_ORPHAN_PLUS_GRANT = (target: string): string =>
  `${target} AUTORITE DE PACKAGE D'APPLICATION\\TOUS LES PACKAGES D'APPLICATION:(OI)(CI)(RX)
                    S-1-15-2-999-999-999:(I)(OI)(CI)(F)
                    AUTORITE NT\\SYSTEM:(I)(OI)(CI)(F)
                    BUILTIN\\Administrateurs:(I)(OI)(CI)(F)

Fichiers correctement traités : 1 ; Échec du traitement de 0 fichiers
`

// A package SID icacls CAN resolve prints as the bare family name, so no
// S-1-15-2 text appears for it at all.
const RESOLVED_PACKAGE_FAMILY = (target: string): string =>
  `${target} Microsoft.WindowsTerminal_8wekyb3d8bbwe:(OI)(CI)(RX)
                    NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                    awin\\neil:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
`

type SpawnCall = { command: string; args: string[] }

type FakeSpawn = {
  calls: SpawnCall[]
  spawnFn: WindowsInstallDirAclProbeOptions['spawnFn']
}

function createFakeSpawn(
  respond: (target: string) => {
    stdout?: string
    exitCode?: number
    error?: string
    hang?: boolean
  }
): FakeSpawn {
  const calls: SpawnCall[] = []
  const spawnFn = (command: string, args: readonly string[] = []): EventEmitter => {
    const target = args[0] ?? ''
    calls.push({ command, args: [...args] })
    const outcome = respond(target)
    const child = new EventEmitter() as EventEmitter & {
      kill: () => void
      stdout: Readable | null
    }
    child.kill = () => undefined
    child.stdout = Readable.from([outcome.stdout ?? ''])
    if (outcome.hang) {
      return child
    }
    // Close only after stdout drains, mirroring the real ordering the probe relies on.
    child.stdout.on('end', () => {
      if (outcome.error) {
        child.emit('error', new Error(outcome.error))
        return
      }
      child.emit('close', outcome.exitCode ?? 0)
    })
    return child
  }
  return { calls, spawnFn: spawnFn as unknown as WindowsInstallDirAclProbeOptions['spawnFn'] }
}

const never = (): Promise<never> => new Promise(() => undefined)

/** Let every pending microtask, timer and immediate the probe could use run. */
async function settleEventLoop(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
  await new Promise((resolve) => setImmediate(resolve))
}

function runProbe(
  options: WindowsInstallDirAclProbeOptions
): Promise<{ name: string; data: CrashReportBreadcrumbData }> {
  return new Promise((resolve) => {
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      env: { LOCALAPPDATA: 'C:\\Users\\neil\\AppData\\Local' },
      osRelease: () => '10.0.26200',
      uiLanguage: () => 'en-US',
      listInstallDirEntries: async () => ENTRIES,
      recordStartBreadcrumb: () => undefined,
      recordDurableBreadcrumb: () => undefined,
      whenTracerSinkReady: () => Promise.resolve(),
      ...options,
      recordBreadcrumb: (name, data) => resolve({ name, data })
    })
  })
}

function probeWithOutput(
  build: (target: string) => string
): Promise<{ name: string; data: CrashReportBreadcrumbData }> {
  return runProbe({ spawnFn: createFakeSpawn((target) => ({ stdout: build(target) })).spawnFn })
}

describe('probeWindowsInstallDirAcl', () => {
  beforeEach(() => {
    resetWindowsInstallDirAclProbeForTest()
  })

  it('reports a clean DACL as unpoisoned', async () => {
    const { name, data } = await probeWithOutput(CLEAN)
    expect(name).toBe(WINDOWS_INSTALL_DIR_ACL_BREADCRUMB)
    expect(data.status).toBe('complete')
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.packageAceCountAcrossTargets).toBe(0)
    expect(data.unresolvedPackageSidCount).toBe(0)
    expect(data.probedTargetCount).toBe(3)
    expect(data.aceLineCountAcrossTargets).toBe(9)
    expect(data.resolvedPackageAceCountAcrossTargets).toBe(0)
    expect(data.wellKnownNameDetectionReliable).toBe(true)
    expect(data.uiLanguage).toBe('en-US')
    expect(data.installPathClass).toBe('localappdata-programs')
    expect(data.windowsBuild).toBe('10.0.26200')
    expect(data.reason).toBeUndefined()
  })

  it('flags an orphan package SID with no well-known package SID present', async () => {
    const { data } = await probeWithOutput(ORPHAN)
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.unresolvedPackageSidCount).toBe(1)
    expect(data.unresolvedPackageSid0).toBe('S-1-15-2-999-999-999')
    expect(data.unresolvedPackageSid1).toBeUndefined()
    expect(data.hasAllApplicationPackages).toBe(false)
    expect(data.hasAllRestrictedAppPackages).toBe(false)
    expect(data.installDirMatchesPoisonSignature).toBe(true)
    expect(data.moduleFileMatchesPoisonSignature).toBe(true)
    expect(data.resourceFileMatchesPoisonSignature).toBe(true)
  })

  it('clears the signature when ALL RESTRICTED APPLICATION PACKAGES is also present', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_RESTRICTED)
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.hasAllRestrictedAppPackages).toBe(true)
    expect(data.unresolvedPackageSidCount).toBe(1)
    expect(data.friendlyNameFallbackUsed).toBe(true)
  })

  it('clears the signature when ALL APPLICATION PACKAGES is also present', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_ALL_APP_PACKAGES)
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.hasAllApplicationPackages).toBe(true)
    expect(data.hasAllRestrictedAppPackages).toBe(false)
  })

  it('keeps the signature when the well-known package ACE is a deny', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_DENIED_ALL_APP_PACKAGES)
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.hasAllApplicationPackages).toBe(false)
    expect(data.nonGrantingWellKnownPackageAceCountAcrossTargets).toBe(3)
    // Still a package ACE, just one that cannot satisfy the orphan.
    expect(data.packageAceCountAcrossTargets).toBe(6)
  })

  it('keeps the signature when the well-known package ACE is inherit-only', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_INHERIT_ONLY_RESTRICTED)
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.hasAllRestrictedAppPackages).toBe(false)
    expect(data.nonGrantingWellKnownPackageAceCountAcrossTargets).toBe(3)
  })

  it('counts capability SIDs separately and does not flag them', async () => {
    const { data } = await probeWithOutput(CAPABILITY_ONLY)
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.capabilitySidCountAcrossTargets).toBe(3)
    expect(data.packageAceCountAcrossTargets).toBe(0)
  })

  it('distinguishes inherited from explicit package ACEs', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_RESTRICTED)
    // Per target: one explicit (OI)(CI)(RX) grant, one inherited orphan.
    expect(data.inheritedPackageAceCountAcrossTargets).toBe(3)
    expect(data.explicitPackageAceCountAcrossTargets).toBe(3)
    expect(data.installDirInheritedPackageAceCount).toBe(1)
  })

  // A localized icacls prints no recognizable well-known package name, so the
  // poison verdict must be marked unreliable rather than trusted.
  it('marks well-known-name detection unreliable when icacls output is localized', async () => {
    const { data } = await probeWithOutput(LOCALIZED_ORPHAN_PLUS_GRANT)
    expect(data.wellKnownNameDetectionReliable).toBe(false)
    expect(data.unresolvedPackageSidCount).toBe(1)
  })

  // The case principal spelling cannot catch: French/Spanish/Japanese keep
  // BUILTIN and NT AUTHORITY while localizing ALL APPLICATION PACKAGES, so a
  // healthy box reports the poison signature and must not read as trustworthy.
  it('marks the verdict unreliable on a non-English UI even when the principals look English', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({
        stdout: PARTLY_LOCALIZED_ORPHAN_PLUS_GRANT(target)
      })).spawnFn,
      uiLanguage: () => 'fr-FR'
    })
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.englishSystemPrincipalSeen).toBe(true)
    expect(data.wellKnownNameDetectionReliable).toBe(false)
    expect(data.uiLanguage).toBe('fr-FR')
  })

  it('marks the verdict unreliable when the UI language cannot be read', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({ stdout: ORPHAN(target) })).spawnFn,
      uiLanguage: () => ''
    })
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.wellKnownNameDetectionReliable).toBe(false)
  })

  // packageAceCount only sees the raw-SID and well-known-name forms, so a
  // resolvable package grant would otherwise read as "no package ACEs at all".
  it('counts package ACEs icacls resolved to a family name separately', async () => {
    const { data } = await probeWithOutput(RESOLVED_PACKAGE_FAMILY)
    expect(data.resolvedPackageAceCountAcrossTargets).toBe(3)
    expect(data.installDirResolvedPackageAceCount).toBe(1)
    expect(data.packageAceCountAcrossTargets).toBe(0)
    expect(data.matchesPoisonSignature).toBe(false)
  })

  it('probes only the install dir plus one dll and one resource file, with no flags', async () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    await runProbe({ spawnFn: fake.spawnFn })
    expect(fake.calls.map((call) => call.args).sort()).toEqual(
      [[INSTALL_DIR], [join(INSTALL_DIR, 'ffmpeg.dll')], [join(INSTALL_DIR, 'icudtl.dat')]].sort()
    )
    for (const call of fake.calls) {
      expect(call.args).toHaveLength(1)
      expect(call.command.toLowerCase()).toContain('icacls.exe')
    }
    const everyArg = fake.calls.flatMap((call) => call.args).join(' ')
    for (const forbidden of ['/T', '/grant', '/deny', '/reset', '/setowner', '/inheritance']) {
      expect(everyArg).not.toContain(forbidden)
    }
  })

  it('records a reason instead of throwing when icacls exits non-zero', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn(() => ({ exitCode: 5 })).spawnFn
    })
    expect(data.probedTargetCount).toBe(0)
    expect(data.installDirReason).toBe('exit 5')
    // Nothing was measured, so the headline verdict must not read as "clean".
    expect(data.matchesPoisonSignature).toBeNull()
    expect(data.reason).toBe('all-targets-failed')
  })

  it('records a reason when the spawn itself errors', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn(() => ({ error: 'ENOENT' })).spawnFn
    })
    expect(data.installDirReason).toBe('spawn: ENOENT')
    expect(data.moduleFileReason).toBe('spawn: ENOENT')
  })

  it('times every hung icacls call out against the budget', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn(() => ({ hang: true })).spawnFn,
      budgetMs: 300
    })
    expect(data.installDirReason).toBe('timeout')
    expect(data.moduleFileReason).toBe('timeout')
    expect(data.resourceFileReason).toBe('timeout')
    expect(data.probedTargetCount).toBe(0)
  })

  // The only path where shared-vs-per-target is observable: the three reads run
  // concurrently, so a per-target budget costs the same wall time — but a listing
  // that eats the whole budget must leave the child reads nothing.
  it('spends one shared budget across every icacls call, not one per target', async () => {
    // Only Date is faked; setImmediate/setTimeout must stay real for the probe to run.
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      const budgetMs = 500
      const { data } = await runProbe({
        spawnFn: createFakeSpawn((target) => ({ stdout: ORPHAN(target) })).spawnFn,
        budgetMs,
        listInstallDirEntries: async () => {
          vi.setSystemTime(Date.now() + budgetMs + 10)
          return ENTRIES
        }
      })
      // Started before the listing, so this one still parsed.
      expect(data.installDirMatchesPoisonSignature).toBe(true)
      expect(data.moduleFileReason).toBe('budget-exhausted')
      expect(data.resourceFileReason).toBe('budget-exhausted')
      expect(data.probedTargetCount).toBe(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('still reports the install dir when listing it never resolves', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({ stdout: ORPHAN(target) })).spawnFn,
      listInstallDirEntries: never,
      budgetMs: 300
    })
    expect(data.reason).toBe('readdir-timeout')
    expect(data.probedTargetCount).toBe(1)
    expect(data.installDirMatchesPoisonSignature).toBe(true)
    expect(data.moduleFileReason).toBe('not-found')
  })

  it('records not-found when no dll or resource file exists in the install dir', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({ stdout: CLEAN(target) })).spawnFn,
      listInstallDirEntries: async () => ['orca.exe']
    })
    expect(data.moduleFileReason).toBe('not-found')
    expect(data.resourceFileReason).toBe('not-found')
    expect(data.probedTargetCount).toBe(1)
  })

  it('records a reason when the install dir cannot be listed', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({ stdout: CLEAN(target) })).spawnFn,
      listInstallDirEntries: async () => {
        throw new Error('EPERM')
      }
    })
    expect(String(data.reason)).toContain('readdir')
    expect(data.probedTargetCount).toBe(1)
  })

  it('records an in-flight marker synchronously, before the first spawn', () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    const started: { name: string; data: CrashReportBreadcrumbData }[] = []
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      env: { LOCALAPPDATA: 'C:\\Users\\neil\\AppData\\Local' },
      osRelease: () => '10.0.26200',
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => ENTRIES,
      recordStartBreadcrumb: (name, data) => started.push({ name, data }),
      recordBreadcrumb: () => undefined
    })
    expect(started).toEqual([
      {
        name: WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
        data: {
          status: 'started',
          installPathClass: 'localappdata-programs',
          windowsBuild: '10.0.26200',
          gpuFallbackActiveThisLaunch: false
        }
      }
    ])
    expect(fake.calls).toHaveLength(0)
  })

  it('never spawns, reads the filesystem or records anything off win32', async () => {
    const fake = createFakeSpawn(() => ({ stdout: '' }))
    const events: string[] = []
    probeWindowsInstallDirAcl({
      platform: 'darwin',
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => {
        events.push('readdir')
        throw new Error('must not read the filesystem off win32')
      },
      recordStartBreadcrumb: () => events.push('start'),
      recordBreadcrumb: () => events.push('record'),
      onDone: () => events.push('done')
    })
    await settleEventLoop()
    expect(fake.calls).toEqual([])
    expect(events).toEqual([])
  })

  it('never spawns, reads the filesystem or records anything in serve mode', async () => {
    const fake = createFakeSpawn(() => ({ stdout: '' }))
    const events: string[] = []
    probeWindowsInstallDirAcl({
      platform: 'win32',
      isServeMode: true,
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => {
        events.push('readdir')
        throw new Error('must not read the filesystem in serve mode')
      },
      recordStartBreadcrumb: () => events.push('start'),
      recordBreadcrumb: () => events.push('record'),
      onDone: () => events.push('done')
    })
    await settleEventLoop()
    expect(fake.calls).toEqual([])
    expect(events).toEqual([])
  })

  // One key per SID: sanitizeCrashReportDetails re-truncates every string detail
  // at 240 chars, so a joined list of real ~84-char SIDs loses the third
  // mid-value — and a mangled SID cannot be correlated across reports.
  it('keeps capped unresolved SIDs intact through the breadcrumb sanitizer', async () => {
    const sids = [0, 1, 2, 3].map(
      (index) =>
        `S-1-15-2-${index}953${index}47845-2214654456-2652434443-${index}42${index}30${index}39-4045166157-2001573463-3053417338`
    )
    const { data } = await probeWithOutput(
      (target) =>
        `${target} ${sids.map((sid) => `${sid}:(I)(OI)(CI)(F)`).join('\n                    ')}\n`
    )
    const sanitized = sanitizeCrashReportDetails(data)
    expect(sanitized.unresolvedPackageSidCount).toBe(4)
    expect(sanitized.unresolvedPackageSid0).toBe(sids[0])
    expect(sanitized.unresolvedPackageSid1).toBe(sids[1])
    expect(sanitized.unresolvedPackageSid2).toBe(sids[2])
    expect(sanitized.unresolvedPackageSid3).toBeUndefined()
  })

  it('carries the GPU fallback state so a report without a GPU child is interpretable', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn((target) => ({ stdout: CLEAN(target) })).spawnFn,
      gpuFallbackActive: true
    })
    expect(data.gpuFallbackActiveThisLaunch).toBe(true)
  })
})

describe('classifyInstallPath', () => {
  const env = {
    LOCALAPPDATA: 'C:\\Users\\neil\\AppData\\Local',
    APPDATA: 'C:\\Users\\neil\\AppData\\Roaming',
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)'
  }

  it.each([
    ['C:\\Users\\neil\\AppData\\Local\\Programs\\orca', 'localappdata-programs'],
    ['C:\\Program Files\\orca', 'program-files'],
    ['C:\\Program Files (x86)\\orca', 'program-files-x86'],
    ['C:\\Users\\neil\\AppData\\Roaming\\orca', 'appdata-roaming'],
    ['D:\\tools\\orca', 'other'],
    // Local (but not Local\Programs) must not be misread as an install root.
    ['C:\\Users\\neil\\AppData\\Local\\orca', 'other']
  ])('classifies %s as %s', (dir, expected) => {
    expect(classifyInstallPath(dir, env)).toBe(expected)
  })

  it('is case- and separator-insensitive', () => {
    expect(classifyInstallPath('c:/users/neil/appdata/local/programs/orca/', env)).toBe(
      'localappdata-programs'
    )
  })

  it('falls back to other when the env vars are missing', () => {
    expect(classifyInstallPath(INSTALL_DIR, {})).toBe('other')
  })
})

describe('parsePackageAuthorityAces', () => {
  // icacls prints the echoed target and the first principal with no reliable
  // separator when the path contains spaces ("C:\Program Files NT SERVICE\…").
  it('strips the echoed target from the first ACE line', () => {
    const target = 'C:\\Program Files\\orca'
    const facts = parsePackageAuthorityAces(
      `${target} S-1-15-2-999-999-999:(I)(OI)(CI)(F)\nNT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)\n`,
      target
    )
    expect(facts.unresolvedPackageSids).toEqual(['S-1-15-2-999-999-999'])
    expect(facts.matchesPoisonSignature).toBe(true)
  })

  // icacls writes OEM-codepage bytes, so a non-ASCII profile name decodes to
  // U+FFFD and the echo no longer matches the path we passed. The orphan is
  // line 1 when inherited, so losing it would report a poisoned box as clean.
  it('detects the orphan when the echoed target is mojibake', () => {
    const facts = parsePackageAuthorityAces(
      ORPHAN('C:\\Users\\J\uFFFDrg\\AppData\\Local\\Programs\\orca'),
      'C:\\Users\\Jörg\\AppData\\Local\\Programs\\orca'
    )
    expect(facts.unresolvedPackageSids).toEqual(['S-1-15-2-999-999-999'])
    expect(facts.inheritedPackageAceCount).toBe(1)
    expect(facts.matchesPoisonSignature).toBe(true)
  })

  // Domain and well-known principals must never be mistaken for a package family
  // name, or resolvedPackageAceCount becomes noise on every machine.
  it('counts only family-name-shaped principals as resolved package ACEs', () => {
    expect(
      parsePackageAuthorityAces(RESOLVED_PACKAGE_FAMILY(INSTALL_DIR), INSTALL_DIR)
    ).toMatchObject({
      resolvedPackageAceCount: 1,
      packageAceCount: 0,
      matchesPoisonSignature: false
    })
    expect(
      parsePackageAuthorityAces(REAL_PROGRAM_FILES, 'C:\\Program Files').resolvedPackageAceCount
    ).toBe(0)
    expect(
      parsePackageAuthorityAces(`${INSTALL_DIR} awin\\build_agent0123456:(F)\n`, INSTALL_DIR)
        .resolvedPackageAceCount
    ).toBe(0)
  })

  it('ignores the trailing summary line and blank lines', () => {
    const facts = parsePackageAuthorityAces(CLEAN(INSTALL_DIR), INSTALL_DIR)
    expect(facts.packageAceCount).toBe(0)
    expect(facts.capabilitySidCount).toBe(0)
    expect(facts.aceLineCount).toBe(3)
  })

  // aceLineCount separates a parse/format surprise from a genuinely clean DACL.
  it('reports zero ACE lines but non-zero output lines when nothing parses', () => {
    const facts = parsePackageAuthorityAces(
      'orca: Access is denied.\nSuccessfully processed 0 files\n',
      INSTALL_DIR
    )
    expect(facts.aceLineCount).toBe(0)
    expect(facts.outputLineCount).toBe(2)
  })

  it('treats the well-known SIDs as satisfying even in raw SID form', () => {
    const facts = parsePackageAuthorityAces(
      `${INSTALL_DIR} S-1-15-2-2:(OI)(CI)(RX)\nS-1-15-2-999:(I)(OI)(CI)(F)\n`,
      INSTALL_DIR
    )
    expect(facts.hasAllRestrictedAppPackages).toBe(true)
    expect(facts.friendlyNameFallbackUsed).toBe(false)
    expect(facts.matchesPoisonSignature).toBe(false)
  })

  // The repro was cleared by an additive grant; a deny grants nothing, so a
  // denied well-known SID must not read as "this box is satisfied".
  it('does not let a denied well-known package SID satisfy an orphan', () => {
    const facts = parsePackageAuthorityAces(
      `${INSTALL_DIR} S-1-15-2-1:(DENY)(F)\nS-1-15-2-999:(I)(OI)(CI)(F)\n`,
      INSTALL_DIR
    )
    expect(facts.hasAllApplicationPackages).toBe(false)
    expect(facts.nonGrantingWellKnownPackageAceCount).toBe(1)
    expect(facts.matchesPoisonSignature).toBe(true)
  })

  // Same for inherit-only in raw SID form: it grants on children, not here.
  it('does not let an inherit-only well-known package SID satisfy an orphan', () => {
    const facts = parsePackageAuthorityAces(
      `${INSTALL_DIR} S-1-15-2-2:(OI)(CI)(IO)(GR,GE)\nS-1-15-2-999:(I)(OI)(CI)(F)\n`,
      INSTALL_DIR
    )
    expect(facts.hasAllRestrictedAppPackages).toBe(false)
    expect(facts.nonGrantingWellKnownPackageAceCount).toBe(1)
    expect(facts.packageAceCount).toBe(2)
    expect(facts.matchesPoisonSignature).toBe(true)
  })

  it('sees no English system principal in localized output', () => {
    const facts = parsePackageAuthorityAces(LOCALIZED_ORPHAN_PLUS_GRANT(INSTALL_DIR), INSTALL_DIR)
    expect(facts.englishSystemPrincipalSeen).toBe(false)
    expect(facts.unresolvedPackageSidCount).toBe(1)
  })
})

describe('durable emit ordering', () => {
  beforeEach(() => {
    resetWindowsInstallDirAclProbeForTest()
  })

  // startSpan is a no-op until initObservability installs the tracer sink, and
  // that happens inside app.whenReady — long after this probe finishes. Emitting
  // durably before then would drop the span, leaving no record of a launch that
  // did not crash, i.e. no base rate for the poison shape.
  it('records into the ring immediately and durably only once the tracer sink exists', async () => {
    const events: string[] = []
    let releaseSink: () => void = () => undefined
    const sinkReady = new Promise<void>((resolve) => {
      releaseSink = resolve
    })
    const fake = createFakeSpawn((target) => ({ stdout: ORPHAN(target) }))
    await new Promise<void>((resolve) => {
      probeWindowsInstallDirAcl({
        platform: 'win32',
        installDir: INSTALL_DIR,
        spawnFn: fake.spawnFn,
        listInstallDirEntries: async () => ENTRIES,
        recordStartBreadcrumb: () => events.push('start'),
        recordBreadcrumb: () => {
          events.push('ring')
          resolve()
        },
        recordDurableBreadcrumb: (_name, data) =>
          events.push(`durable:${String(data.matchesPoisonSignature)}`),
        whenTracerSinkReady: () => sinkReady
      })
    })
    await settleEventLoop()
    expect(events).toEqual(['start', 'ring'])
    releaseSink()
    await settleEventLoop()
    expect(events).toEqual(['start', 'ring', 'durable:true'])
  })
})

describe('synchronous call safety', () => {
  beforeEach(() => {
    resetWindowsInstallDirAclProbeForTest()
  })

  // The call site runs at main-process module scope, so a throw here would abort
  // startup and no window would ever be created.
  it('never throws out of the synchronous call and still probes when the start recorder fails', async () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    const result = new Promise<CrashReportBreadcrumbData>((resolve) => {
      expect(() =>
        probeWindowsInstallDirAcl({
          platform: 'win32',
          installDir: INSTALL_DIR,
          spawnFn: fake.spawnFn,
          listInstallDirEntries: async () => ENTRIES,
          whenTracerSinkReady: () => Promise.resolve(),
          recordDurableBreadcrumb: () => undefined,
          recordStartBreadcrumb: () => {
            throw new Error('recorder exploded')
          },
          recordBreadcrumb: (_name, data) => resolve(data)
        })
      ).not.toThrow()
    })
    expect((await result).status).toBe('complete')
  })

  // Resolving it calls an Electron binding before app.whenReady, and the start
  // marker discards the value anyway.
  it('does not resolve the UI language on the synchronous path', () => {
    const uiLanguageCalls: string[] = []
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      spawnFn: createFakeSpawn((target) => ({ stdout: CLEAN(target) })).spawnFn,
      listInstallDirEntries: async () => ENTRIES,
      uiLanguage: () => {
        uiLanguageCalls.push('resolved')
        return 'en-US'
      },
      recordStartBreadcrumb: () => undefined,
      recordBreadcrumb: () => undefined,
      recordDurableBreadcrumb: () => undefined,
      whenTracerSinkReady: () => Promise.resolve()
    })
    expect(uiLanguageCalls).toEqual([])
  })
})

describe('probe re-entry', () => {
  beforeEach(() => {
    resetWindowsInstallDirAclProbeForTest()
  })

  // A second call must cost nothing: the DACL cannot change mid-process.
  it('spawns icacls only for the first call per process', async () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    await runProbe({ spawnFn: fake.spawnFn })
    const afterFirst = fake.calls.length
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => ENTRIES,
      recordStartBreadcrumb: () => undefined,
      recordBreadcrumb: () => undefined
    })
    expect(fake.calls).toHaveLength(afterFirst)
  })
})

// Verbatim `icacls "C:\\Program Files"` output from Windows 11 build 26200.
const REAL_PROGRAM_FILES = `C:\\Program Files NT SERVICE\\TrustedInstaller:(F)
                     NT SERVICE\\TrustedInstaller:(CI)(IO)(F)
                     NT AUTHORITY\\SYSTEM:(M)
                     NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
                     BUILTIN\\Administrators:(M)
                     BUILTIN\\Administrators:(OI)(CI)(IO)(F)
                     BUILTIN\\Users:(RX)
                     BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)
                     CREATOR OWNER:(OI)(CI)(IO)(F)
                     APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)
                     APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
                     APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(RX)
                     APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
`

describe('real icacls output', () => {
  it('reads both well-known package principals off a stock C:\\Program Files DACL', () => {
    const facts = parsePackageAuthorityAces(REAL_PROGRAM_FILES, 'C:\\Program Files')
    expect(facts.hasAllApplicationPackages).toBe(true)
    expect(facts.hasAllRestrictedAppPackages).toBe(true)
    expect(facts.packageAceCount).toBe(4)
    expect(facts.explicitPackageAceCount).toBe(4)
    // Two of the four are (IO): they grant on children, not on this directory.
    expect(facts.nonGrantingWellKnownPackageAceCount).toBe(2)
    expect(facts.unresolvedPackageSidCount).toBe(0)
    expect(facts.englishSystemPrincipalSeen).toBe(true)
    expect(facts.matchesPoisonSignature).toBe(false)
  })
})
