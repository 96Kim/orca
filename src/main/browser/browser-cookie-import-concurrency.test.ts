import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { appGetPathMock, sessionFromPartitionMock, snapshotClearIdentitiesMock } = vi.hoisted(
  () => ({
    appGetPathMock: vi.fn(),
    sessionFromPartitionMock: vi.fn(),
    snapshotClearIdentitiesMock: vi.fn()
  })
)

vi.mock('electron', () => ({
  app: { getPath: appGetPathMock },
  dialog: { showOpenDialog: vi.fn() },
  session: { fromPartition: sessionFromPartitionMock }
}))
vi.mock('./browser-cookie-clear-store', () => ({
  openCookieClearStore: (targetSession: {
    cookies: {
      get: (filter: object) => Promise<unknown>
      remove: (url: string, name: string) => Promise<void>
    }
  }) => ({
    get: (filter: object) => targetSession.cookies.get(filter),
    remove: (url: string, name: string) => targetSession.cookies.remove(url, name),
    snapshotClearIdentities: snapshotClearIdentitiesMock,
    restoreClearIdentities: async () => undefined,
    dispose: () => undefined
  })
}))

import { importCookiesFromBrowser, importCookiesFromFile } from './browser-cookie-import'
import { createChromiumCookieTestDatabase } from './browser-cookie-import-test-database'
import { acquireCookieMutationLock, withCookieMutationLock } from './browser-cookie-import-clear'

/**
 * STA-4601: two imports on one partition must not interleave on the live jar.
 *
 * Nothing serialises imports per partition — neither the renderer IPC handler nor the runtime RPC
 * method — so before this change the lock covered the clear alone and was released before the
 * writes and the rollback. That let import A's rollback remove cookies import B had already
 * written and reported as imported.
 *
 * These tests drive the lock primitive directly with deterministic interleavings rather than
 * racing two real imports, so a failure names the ordering rule that broke instead of flaking.
 */
describe('cookie mutation lock', () => {
  it('serialises two transactions on the same owner', async () => {
    const owner = {}
    const order: string[] = []

    const first = withCookieMutationLock(owner, async () => {
      order.push('A:clear')
      await Promise.resolve()
      order.push('A:write')
    })
    // Why: started before A resolves, so an unserialised implementation interleaves here.
    const second = withCookieMutationLock(owner, async () => {
      order.push('B:clear')
      await Promise.resolve()
      order.push('B:write')
    })

    await Promise.all([first, second])

    expect(order).toEqual(['A:clear', 'A:write', 'B:clear', 'B:write'])
  })

  it('does not serialise across different owners', async () => {
    // Why: the lock is per partition. Two different profiles must still import concurrently.
    const order: string[] = []
    const a = withCookieMutationLock({}, async () => {
      order.push('a:start')
      await Promise.resolve()
      order.push('a:end')
    })
    const b = withCookieMutationLock({}, async () => {
      order.push('b:start')
      await Promise.resolve()
      order.push('b:end')
    })

    await Promise.all([a, b])

    expect(order).toContain('a:end')
    expect(order).toContain('b:end')
    // Interleaved rather than strictly sequential.
    expect(order).not.toEqual(['a:start', 'a:end', 'b:start', 'b:end'])
  })

  it('releases the lock when the transaction throws, so the next import is not wedged', async () => {
    const owner = {}

    await expect(
      withCookieMutationLock(owner, async () => {
        throw new Error('clear rejected')
      })
    ).rejects.toThrow('clear rejected')

    // Why: a failed import must not leave the partition permanently locked.
    await expect(withCookieMutationLock(owner, async () => 'second ran')).resolves.toBe(
      'second ran'
    )
  })

  it('holds across an explicit acquire/release so a rollback stays inside the transaction', async () => {
    // Why: path A takes the lock directly rather than through a callback, because its rollback runs
    // in a finally block. A stale rollback outside the lock is the STA-4601 defect.
    const owner = {}
    const order: string[] = []

    const release = await acquireCookieMutationLock(owner)
    const queued = withCookieMutationLock(owner, async () => {
      order.push('B:clear')
    })

    order.push('A:replace')
    await Promise.resolve()
    order.push('A:rollback')
    release()

    await queued

    expect(order).toEqual(['A:replace', 'A:rollback', 'B:clear'])
  })

  it('leaves the lock usable if a holder releases twice', async () => {
    const owner = {}
    const release = await acquireCookieMutationLock(owner)
    release()
    release()

    await expect(withCookieMutationLock(owner, async () => 'ok')).resolves.toBe('ok')
  })
})

/**
 * The primitive tests above prove the lock works. They would ALL still pass if the importer stopped
 * calling it, because they never run an import — so on their own they are not a detector for the
 * bug this change fixes. These tests drive two real concurrent imports into one partition and
 * assert the second cannot begin until the first has finished writing.
 */
describe('two concurrent imports into one partition', () => {
  let tmpDir: string
  let events: string[]
  let cookiesGetMock: ReturnType<typeof vi.fn>
  let cookiesRemoveMock: ReturnType<typeof vi.fn>
  let cookiesSetMock: ReturnType<typeof vi.fn>
  let releaseFirstWrite: () => void

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'orca-cookie-concurrency-'))
    appGetPathMock.mockReturnValue(join(tmpDir, 'userData'))
    events = []
    // Why: the clear asserts its snapshot covers the removal plan, so a stub returning [] fails
    // the import before it ever reaches a write — and the ordering assertion would pass vacuously.
    snapshotClearIdentitiesMock
      .mockReset()
      .mockImplementation(async (items: { cookie: Record<string, unknown>; url: string }[]) =>
        items.map(({ cookie: entry, url }) => ({ url, ...entry }))
      )

    cookiesGetMock = vi.fn().mockResolvedValue([
      { domain: '.a.example', name: 'old-a', value: 'v', path: '/', secure: true },
      { domain: '.b.example', name: 'old-b', value: 'v', path: '/', secure: true }
    ])
    cookiesRemoveMock = vi.fn(async (_url: string, name: string) => {
      events.push(`remove:${name}`)
    })
    const firstWrite = new Promise<void>((resolve) => {
      releaseFirstWrite = resolve
    })
    cookiesSetMock = vi.fn(async (cookie: { name: string }) => {
      events.push(`set:${cookie.name}`)
      // Why: hold the FIRST import inside its write so a second import has a real opportunity to
      // interleave. Without the lock it takes that opportunity; with it, it waits.
      if (cookie.name === 'new-a') {
        await firstWrite
      }
    })

    // Why: Electron returns the SAME Session instance for a given partition string, which is what
    // makes a per-session lock a per-partition lock. Returning a fresh object per call here would
    // make this test pass against an unlocked implementation.
    const stableSession = {
      cookies: { get: cookiesGetMock, remove: cookiesRemoveMock, set: cookiesSetMock }
    }
    sessionFromPartitionMock.mockReset().mockReturnValue(stableSession)
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function writeSource(name: string, domain: string): string {
    const filePath = join(tmpDir, `${name}.json`)
    writeFileSync(
      filePath,
      JSON.stringify([{ domain, name, value: 'imported', path: '/', secure: true }])
    )
    return filePath
  }

  it('does not let the second import touch the jar until the first has finished writing', async () => {
    const fileA = writeSource('new-a', '.a.example')
    const fileB = writeSource('new-b', '.b.example')

    const first = importCookiesFromFile(fileA, 'persist:concurrency-test')
    // Let the first import reach its write and block there.
    await new Promise((resolve) => setTimeout(resolve, 5))
    const second = importCookiesFromFile(fileB, 'persist:concurrency-test')
    await new Promise((resolve) => setTimeout(resolve, 20))

    // At this instant the first import is still inside its write. Nothing from the second may have
    // touched the jar yet — this is the assertion that fails if the call sites drop the lock.
    expect(events).not.toContain('remove:old-b')
    expect(events).not.toContain('set:new-b')

    releaseFirstWrite()
    const [resultA, resultB] = await Promise.all([first, second])

    // Why: if either import failed, the ordering assertions below would pass vacuously.
    expect(resultA.ok).toBe(true)
    expect(resultB.ok).toBe(true)

    // And the full ordering is serial, not interleaved.
    expect(events.indexOf('set:new-a')).toBeLessThan(events.indexOf('remove:old-b'))
  })
})

/**
 * Path B (native Chromium) has its own lock acquisition, and the file-import test above cannot
 * reach it. Without this, deleting path B's withCookieMutationLock leaves every test green — which
 * a review round confirmed by mutation before this was added.
 */
describe('two concurrent NATIVE imports into one partition', () => {
  let tmpDir: string
  let events: string[]
  let cookiesSetMock: ReturnType<typeof vi.fn>
  let releaseFirstWrite: () => void
  let platformSpy: { mockRestore: () => void }

  function chromeBrowser(cookiesPath: string) {
    return {
      family: 'chrome' as const,
      label: 'Google Chrome',
      cookiesPath,
      keychainService: 'Chrome Safe Storage',
      keychainAccount: 'Chrome',
      profiles: [{ name: 'Default', directory: 'Default' }],
      selectedProfile: 'Default'
    }
  }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'orca-cookie-native-concurrency-'))
    appGetPathMock.mockReturnValue(join(tmpDir, 'userData'))
    events = []
    // Why: an EMPTY jar makes removeTransplantableCookies return before it clears, so the clear
    // would never run and a clearData assertion would pass vacuously. Seed it.
    snapshotClearIdentitiesMock
      .mockReset()
      .mockImplementation(async (items: { cookie: Record<string, unknown>; url: string }[]) =>
        items.map(({ cookie: entry, url }) => ({ url, ...entry }))
      )
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('darwin')

    const firstWrite = new Promise<void>((resolve) => {
      releaseFirstWrite = resolve
    })
    cookiesSetMock = vi.fn(async (cookie: { name: string }) => {
      events.push(`set:${cookie.name}`)
      if (cookie.name === 'first') {
        await firstWrite
      }
    })
    const stableSession = {
      cookies: {
        get: vi
          .fn()
          .mockResolvedValue([
            { domain: '.stale.example', name: 'stale', value: 'v', path: '/', secure: true }
          ]),
        remove: vi.fn().mockResolvedValue(undefined),
        set: cookiesSetMock,
        flushStore: vi.fn().mockResolvedValue(undefined)
      },
      clearData: vi.fn(async () => {
        events.push('clearData')
      }),
      setUserAgent: vi.fn()
    }
    sessionFromPartitionMock.mockReset().mockReturnValue(stableSession)
  })

  afterEach(() => {
    platformSpy.mockRestore()
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('does not let a second native import clear while the first is still writing', async () => {
    const sourceA = join(tmpDir, 'ChromeA', 'Default', 'Network', 'Cookies')
    const sourceB = join(tmpDir, 'ChromeB', 'Default', 'Network', 'Cookies')
    createChromiumCookieTestDatabase(sourceA, [
      { domain: '.a.example', name: 'first', value: 'v' }
    ]).close()
    createChromiumCookieTestDatabase(sourceB, [
      { domain: '.b.example', name: 'second', value: 'v' }
    ]).close()
    // Why: a live target DB so the cold-init probe does not run and change the event ordering.
    createChromiumCookieTestDatabase(
      join(tmpDir, 'userData', 'Partitions', 'native-conc', 'Network', 'Cookies'),
      []
    ).close()

    const first = importCookiesFromBrowser(chromeBrowser(sourceA), 'persist:native-conc')
    await new Promise((resolve) => setTimeout(resolve, 10))
    const second = importCookiesFromBrowser(chromeBrowser(sourceB), 'persist:native-conc')
    await new Promise((resolve) => setTimeout(resolve, 25))

    // The first import is parked inside its write. The second must not have cleared yet — this is
    // the assertion that fails if path B stops taking the lock.
    expect(events.filter((e) => e === 'clearData')).toHaveLength(1)
    expect(events).not.toContain('set:second')

    releaseFirstWrite()
    const [resultA, resultB] = await Promise.all([first, second])

    // Why: a failed import would make the ordering assertions pass vacuously.
    expect(resultA.ok).toBe(true)
    expect(resultB.ok).toBe(true)
    expect(events.indexOf('set:first')).toBeLessThan(events.lastIndexOf('clearData'))
  })
})
