// Pins the release side of the pre-ready span gate: diagnostics that run before
// app.whenReady defer their durable emit on `whenTracerSinkReady()`, so a path
// through `initObservability` that forgets to release it would silently drop
// that half forever — the exact failure the gate exists to prevent.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('./local-file-sink', () => ({
  createLocalFileSink: () => ({
    push: () => undefined,
    flush: () => undefined,
    close: () => undefined
  }),
  DEFAULT_MAX_FILES: 5,
  getRotatedFamilySize: () => 0
}))

const CONSENT_ENV_VARS = [
  'CI',
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'CIRCLECI',
  'TRAVIS',
  'BUILDKITE',
  'JENKINS_URL',
  'TEAMCITY_VERSION',
  'ORCA_DIAGNOSTICS_DISABLED',
  'ORCA_TELEMETRY_DISABLED',
  'DO_NOT_TRACK'
]

let savedEnv: Record<string, string | undefined> = {}

async function settled(promise: Promise<void>): Promise<boolean> {
  return Promise.race([promise.then(() => true), Promise.resolve().then(() => false)])
}

/** Fresh registry per case: the gate is a module-level promise that latches. */
async function loadGate(): Promise<{
  initObservability: () => unknown
  whenTracerSinkReady: () => Promise<void>
}> {
  vi.resetModules()
  const { initObservability } = await import('./index')
  const { whenTracerSinkReady } = await import('./tracer-sink-ready')
  return { initObservability, whenTracerSinkReady }
}

beforeEach(() => {
  savedEnv = Object.fromEntries(CONSENT_ENV_VARS.map((name) => [name, process.env[name]]))
  for (const name of CONSENT_ENV_VARS) {
    delete process.env[name]
  }
})

afterEach(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) {
      delete process.env[name]
    } else {
      process.env[name] = value
    }
  }
})

describe('tracer sink ready gate', () => {
  it('stays pending until initObservability runs', async () => {
    const { initObservability, whenTracerSinkReady } = await loadGate()

    expect(await settled(whenTracerSinkReady())).toBe(false)

    initObservability()

    expect(await settled(whenTracerSinkReady())).toBe(true)
  })

  // The sink is never installed here, so a gate tied to installLocalSink would
  // block a deferred durable breadcrumb for the life of the process.
  it('releases even when diagnostics are disabled and no sink is installed', async () => {
    process.env.ORCA_DIAGNOSTICS_DISABLED = '1'
    const { initObservability, whenTracerSinkReady } = await loadGate()

    initObservability()

    expect(await settled(whenTracerSinkReady())).toBe(true)
  })
})
