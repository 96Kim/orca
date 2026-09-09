import { ipcMain } from 'electron'
import type { ExecutionHostId } from '../../shared/execution-host'
import {
  connectBitbucket,
  disconnectBitbucket,
  getBitbucketConnectionStatus,
  type BitbucketConnectArgs,
  type BitbucketConnectResult,
  type BitbucketConnectionStatus
} from '../bitbucket/credential-connection'
import {
  BITBUCKET_PR_MERGE_METHODS,
  type BitbucketPRMergeMethod
} from '../../shared/bitbucket-merge-methods'
import type { BitbucketMergeResult } from '../bitbucket/pull-request-merge'
import type { PRComment } from '../../shared/github/comment-types'
import { _resetPreflightCache } from './preflight'

function optionalString(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

function isValidRepoPath(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

function isValidPrNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0
}

function isValidBody(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

function isValidMergeMethod(value: unknown): value is BitbucketPRMergeMethod {
  return (
    typeof value === 'string' && (BITBUCKET_PR_MERGE_METHODS as readonly string[]).includes(value)
  )
}

function normalizeConnectInput(value: unknown): BitbucketConnectArgs | null {
  if (!value || typeof value !== 'object') {
    return null
  }
  const raw = value as Record<string, unknown>
  if (raw.authMode !== 'token' && raw.authMode !== 'basic') {
    return null
  }
  return {
    authMode: raw.authMode,
    accessToken: optionalString(raw.accessToken),
    email: optionalString(raw.email),
    apiToken: optionalString(raw.apiToken),
    baseUrl: optionalString(raw.baseUrl)
  }
}

export function registerBitbucketHandlers(): void {
  ipcMain.handle(
    'bitbucket:connect',
    async (_event, args: unknown): Promise<BitbucketConnectResult> => {
      const input = normalizeConnectInput(args)
      if (!input) {
        return { ok: false, error: 'Invalid Bitbucket credentials' }
      }
      const result = await connectBitbucket(input)
      if (result.ok) {
        // Preflight caches source-control status per session; reset so the card
        // reflects the new connection without a relaunch.
        _resetPreflightCache()
      }
      return result
    }
  )

  ipcMain.handle('bitbucket:disconnect', async (): Promise<void> => {
    disconnectBitbucket()
    _resetPreflightCache()
  })

  ipcMain.handle('bitbucket:status', async (): Promise<BitbucketConnectionStatus> => {
    return getBitbucketConnectionStatus()
  })

  ipcMain.handle(
    'bitbucket:mergePR',
    async (_event, args: unknown): Promise<BitbucketMergeResult> => {
      if (!args || typeof args !== 'object') {
        return { ok: false, error: 'Invalid merge arguments.' }
      }
      const raw = args as Record<string, unknown>
      if (!isValidRepoPath(raw.repoPath) || !isValidPrNumber(raw.prNumber)) {
        return { ok: false, error: 'Invalid merge arguments.' }
      }
      const method = raw.method !== undefined ? raw.method : 'merge_commit'
      if (!isValidMergeMethod(method)) {
        return { ok: false, error: 'Invalid merge strategy.' }
      }
      const closeSourceBranch =
        typeof raw.closeSourceBranch === 'boolean' ? raw.closeSourceBranch : undefined
      const executionHostId =
        typeof raw.executionHostId === 'string'
          ? (raw.executionHostId as ExecutionHostId)
          : undefined

      const { mergeBitbucketPullRequest } = await import('../bitbucket/pull-request-merge')
      return mergeBitbucketPullRequest(
        raw.repoPath,
        raw.prNumber,
        method,
        closeSourceBranch,
        executionHostId
      )
    }
  )

  ipcMain.handle(
    'bitbucket:closePR',
    async (_event, args: unknown): Promise<BitbucketMergeResult> => {
      if (!args || typeof args !== 'object') {
        return { ok: false, error: 'Invalid close arguments.' }
      }
      const raw = args as Record<string, unknown>
      if (!isValidRepoPath(raw.repoPath) || !isValidPrNumber(raw.prNumber)) {
        return { ok: false, error: 'Invalid close arguments.' }
      }
      const executionHostId =
        typeof raw.executionHostId === 'string'
          ? (raw.executionHostId as ExecutionHostId)
          : undefined

      const { declineBitbucketPullRequest } = await import('../bitbucket/pull-request-merge')
      return declineBitbucketPullRequest(raw.repoPath, raw.prNumber, executionHostId)
    }
  )

  ipcMain.handle('bitbucket:getPRComments', async (_event, args: unknown): Promise<PRComment[]> => {
    if (!args || typeof args !== 'object') {
      return []
    }
    const raw = args as Record<string, unknown>
    if (!isValidRepoPath(raw.repoPath) || !isValidPrNumber(raw.prNumber)) {
      return []
    }
    const executionHostId =
      typeof raw.executionHostId === 'string' ? (raw.executionHostId as ExecutionHostId) : undefined

    const { fetchBitbucketPRComments } = await import('../bitbucket/comments')
    const { hostedReviewSshConnectionId } =
      await import('../source-control/hosted-review-execution-host')
    const connectionId = hostedReviewSshConnectionId(executionHostId ?? 'local')
    return fetchBitbucketPRComments(raw.repoPath, raw.prNumber, connectionId)
  })

  ipcMain.handle(
    'bitbucket:addPRComment',
    async (
      _event,
      args: unknown
    ): Promise<{ ok: true; comment: PRComment } | { ok: false; error: string }> => {
      if (!args || typeof args !== 'object') {
        return { ok: false, error: 'Invalid comment arguments.' }
      }
      const raw = args as Record<string, unknown>
      if (
        !isValidRepoPath(raw.repoPath) ||
        !isValidPrNumber(raw.prNumber) ||
        !isValidBody(raw.body)
      ) {
        return { ok: false, error: 'Invalid comment arguments.' }
      }
      const executionHostId =
        typeof raw.executionHostId === 'string'
          ? (raw.executionHostId as ExecutionHostId)
          : undefined
      const { hostedReviewSshConnectionId } =
        await import('../source-control/hosted-review-execution-host')
      const connectionId = hostedReviewSshConnectionId(executionHostId ?? 'local')

      if (typeof raw.parentId === 'number' && Number.isInteger(raw.parentId) && raw.parentId > 0) {
        const rootCommentId =
          typeof raw.rootCommentId === 'number' &&
          Number.isInteger(raw.rootCommentId) &&
          raw.rootCommentId > 0
            ? raw.rootCommentId
            : undefined
        const { replyBitbucketPRComment } = await import('../bitbucket/comments')
        return replyBitbucketPRComment(
          raw.repoPath,
          raw.prNumber,
          raw.parentId,
          raw.body,
          connectionId,
          {},
          rootCommentId
        )
      }

      const inline =
        raw.inline && typeof raw.inline === 'object'
          ? {
              path: String((raw.inline as Record<string, unknown>).path ?? ''),
              line: Number((raw.inline as Record<string, unknown>).line ?? 0)
            }
          : undefined

      const { addBitbucketPRComment } = await import('../bitbucket/comments')
      return addBitbucketPRComment(
        raw.repoPath,
        raw.prNumber,
        raw.body,
        connectionId,
        {},
        inline?.path && inline.line > 0 ? inline : undefined
      )
    }
  )

  ipcMain.handle(
    'bitbucket:replyPRComment',
    async (
      _event,
      args: unknown
    ): Promise<{ ok: true; comment: PRComment } | { ok: false; error: string }> => {
      if (!args || typeof args !== 'object') {
        return { ok: false, error: 'Invalid reply arguments.' }
      }
      const raw = args as Record<string, unknown>
      if (
        !isValidRepoPath(raw.repoPath) ||
        !isValidPrNumber(raw.prNumber) ||
        !isValidBody(raw.body) ||
        typeof raw.parentId !== 'number' ||
        !Number.isInteger(raw.parentId) ||
        raw.parentId <= 0
      ) {
        return { ok: false, error: 'Invalid reply arguments.' }
      }
      const rootCommentId =
        typeof raw.rootCommentId === 'number' &&
        Number.isInteger(raw.rootCommentId) &&
        raw.rootCommentId > 0
          ? raw.rootCommentId
          : undefined
      const executionHostId =
        typeof raw.executionHostId === 'string'
          ? (raw.executionHostId as ExecutionHostId)
          : undefined
      const { replyBitbucketPRComment } = await import('../bitbucket/comments')
      const { hostedReviewSshConnectionId } =
        await import('../source-control/hosted-review-execution-host')
      const connectionId = hostedReviewSshConnectionId(executionHostId ?? 'local')
      return replyBitbucketPRComment(
        raw.repoPath,
        raw.prNumber,
        raw.parentId,
        raw.body,
        connectionId,
        {},
        rootCommentId
      )
    }
  )
}
