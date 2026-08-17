import { EventEmitter } from 'node:events'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { beforeEach, describe, expect, it } from 'vitest'
import type { CrashReportBreadcrumbData } from '../../shared/crash-reporting'
import {
  classifyInstallPath,
  probeWindowsInstallDirAcl,
  resetWindowsInstallDirAclProbeForTest,
  WINDOWS_INSTALL_DIR_ACL_BREADCRUMB,
  type WindowsInstallDirAclProbeOptions
} from './windows-install-dir-acl-probe'
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

const CAPABILITY_ONLY = (target: string): string =>
  `${target} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                    BUILTIN\\Administrators:(OI)(CI)(F)
                    awin\\neil:(OI)(CI)(F)
                    S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575:(S,X)

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

function runProbe(
  options: WindowsInstallDirAclProbeOptions
): Promise<{ name: string; data: CrashReportBreadcrumbData }> {
  return new Promise((resolve) => {
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      env: { LOCALAPPDATA: 'C:\\Users\\neil\\AppData\\Local' },
      osRelease: () => '10.0.26200',
      listInstallDirEntries: async () => ENTRIES,
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
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.packageAceCount).toBe(0)
    expect(data.unresolvedPackageSidCount).toBe(0)
    expect(data.probedTargetCount).toBe(3)
    expect(data.installPathClass).toBe('localappdata-programs')
    expect(data.windowsBuild).toBe('10.0.26200')
  })

  it('flags an orphan package SID with no well-known package SID present', async () => {
    const { data } = await probeWithOutput(ORPHAN)
    expect(data.matchesPoisonSignature).toBe(true)
    expect(data.unresolvedPackageSidCount).toBe(1)
    expect(data.unresolvedPackageSids).toBe('S-1-15-2-999-999-999')
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

  it('counts capability SIDs separately and does not flag them', async () => {
    const { data } = await probeWithOutput(CAPABILITY_ONLY)
    expect(data.matchesPoisonSignature).toBe(false)
    expect(data.capabilitySidCount).toBe(3)
    expect(data.packageAceCount).toBe(0)
  })

  it('distinguishes inherited from explicit package ACEs', async () => {
    const { data } = await probeWithOutput(ORPHAN_PLUS_RESTRICTED)
    // Per target: one explicit (OI)(CI)(RX) grant, one inherited orphan.
    expect(data.inheritedPackageAceCount).toBe(3)
    expect(data.explicitPackageAceCount).toBe(3)
    expect(data.installDirInheritedPackageAceCount).toBe(1)
  })

  it('probes only the install dir plus one dll and one resource file, with no flags', async () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    await runProbe({ spawnFn: fake.spawnFn })
    expect(fake.calls.map((call) => call.args)).toEqual([
      [INSTALL_DIR],
      [join(INSTALL_DIR, 'ffmpeg.dll')],
      [join(INSTALL_DIR, 'icudtl.dat')]
    ])
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
    expect(data.matchesPoisonSignature).toBe(false)
  })

  it('records a reason when the spawn itself errors', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn(() => ({ error: 'ENOENT' })).spawnFn
    })
    expect(data.installDirReason).toBe('spawn: ENOENT')
    expect(data.moduleFileReason).toBe('spawn: ENOENT')
  })

  it('emits a breadcrumb with a timeout reason when icacls never exits', async () => {
    const { data } = await runProbe({
      spawnFn: createFakeSpawn(() => ({ hang: true })).spawnFn
    })
    expect(data.installDirReason).toBe('timeout')
    expect(data.probedTargetCount).toBe(0)
  }, 20_000)

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

  it('never spawns off win32', () => {
    const fake = createFakeSpawn(() => ({ stdout: '' }))
    let recorded = false
    probeWindowsInstallDirAcl({
      platform: 'darwin',
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => {
        throw new Error('must not read the filesystem off win32')
      },
      recordBreadcrumb: () => {
        recorded = true
      }
    })
    expect(fake.calls).toHaveLength(0)
    expect(recorded).toBe(false)
  })

  it('never spawns in serve mode', () => {
    const fake = createFakeSpawn(() => ({ stdout: '' }))
    probeWindowsInstallDirAcl({
      platform: 'win32',
      isServeMode: true,
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      recordBreadcrumb: () => undefined
    })
    expect(fake.calls).toHaveLength(0)
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

  it('ignores the trailing summary line and blank lines', () => {
    const facts = parsePackageAuthorityAces(CLEAN(INSTALL_DIR), INSTALL_DIR)
    expect(facts.packageAceCount).toBe(0)
    expect(facts.capabilitySidCount).toBe(0)
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
})

describe('probe re-entry', () => {
  beforeEach(() => {
    resetWindowsInstallDirAclProbeForTest()
  })

  // openMainWindow runs again on re-activation; the second call must cost nothing.
  it('spawns icacls only for the first call per process', async () => {
    const fake = createFakeSpawn((target) => ({ stdout: CLEAN(target) }))
    await runProbe({ spawnFn: fake.spawnFn })
    const afterFirst = fake.calls.length
    probeWindowsInstallDirAcl({
      platform: 'win32',
      installDir: INSTALL_DIR,
      spawnFn: fake.spawnFn,
      listInstallDirEntries: async () => ENTRIES,
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
    expect(facts.unresolvedPackageSidCount).toBe(0)
    expect(facts.matchesPoisonSignature).toBe(false)
  })
})
