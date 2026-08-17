import type { spawn } from 'node:child_process'
import { getIcaclsExePath } from '../win32-utils'
import type { TargetOutcome } from './windows-install-dir-acl-breadcrumb-fields'
import { parsePackageAuthorityAces } from './windows-package-authority-aces'

/**
 * Read-only single-path DACL read. The entire argv is one path: no /grant,
 * /deny, /reset, /setowner — and never /T, because a recursive walk on a real
 * profile measured 62s (see windows-user-data-acl.ts).
 */
function runIcacls(
  spawnFn: typeof spawn,
  target: string,
  timeoutMs: number
): Promise<{ stdout: string } | { reason: string }> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>
    try {
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

/** @param deadline shared wall-clock budget for the whole probe, not per target. */
export async function readTargetDacl(
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
