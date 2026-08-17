/**
 * Gate for diagnostics that run before `initObservability()`.
 *
 * Why: `startSpan` is a no-op while the active sink is unset, and the sink is
 * installed inside `app.whenReady()`. A pre-ready caller that emits durably
 * loses the span half silently, so it has no record at all on a launch that
 * did not crash — awaiting this keeps that base-rate signal.
 */

let markReady: (() => void) | undefined
const ready = new Promise<void>((resolve) => {
  markReady = resolve
})

/** Resolves once the sink decision is made — including the disabled path, or
 *  waiters would block forever on a machine with telemetry off. */
export function markTracerSinkReady(): void {
  markReady?.()
  markReady = undefined
}

export function whenTracerSinkReady(): Promise<void> {
  return ready
}
