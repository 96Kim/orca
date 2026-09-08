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
import type { BitbucketPRMergeMethod } from '../../shared/bitbucket-merge-methods'
import { _resetPreflightCache } from './preflight'

function optionalString(value: unknown): string | null {
  return typeof value === 'string' ? value : null
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
    async (
      _event,
      args: {
        repoPath: string
        prNumber: number
        method?: BitbucketPRMergeMethod
        closeSourceBranch?: boolean
        executionHostId?: ExecutionHostId
      }
    ) => {
      const { mergeBitbucketPullRequest } = await import('../bitbucket/pull-request-merge')
      return mergeBitbucketPullRequest(
        args.repoPath,
        args.prNumber,
        args.method,
        args.closeSourceBranch,
        args.executionHostId
      )
    }
  )

  ipcMain.handle(
    'bitbucket:closePR',
    async (
      _event,
      args: { repoPath: string; prNumber: number; executionHostId?: ExecutionHostId }
    ) => {
      const { declineBitbucketPullRequest } = await import('../bitbucket/pull-request-merge')
      return declineBitbucketPullRequest(args.repoPath, args.prNumber, args.executionHostId)
    }
  )

  ipcMain.handle(
    'bitbucket:getPRComments',
    async (
      _event,
      args: { repoPath: string; prNumber: number; executionHostId?: ExecutionHostId }
    ) => {
      const { fetchBitbucketPRComments } = await import('../bitbucket/comments')
      const { hostedReviewSshConnectionId } =
        await import('../source-control/hosted-review-execution-host')
      const connectionId = hostedReviewSshConnectionId(args.executionHostId ?? 'local')
      return fetchBitbucketPRComments(args.repoPath, args.prNumber, connectionId)
    }
  )

  ipcMain.handle(
    'bitbucket:addPRComment',
    async (
      _event,
      args: {
        repoPath: string
        prNumber: number
        body: string
        parentId?: number
        inline?: { path: string; line: number }
        executionHostId?: ExecutionHostId
      }
    ) => {
      const { hostedReviewSshConnectionId } =
        await import('../source-control/hosted-review-execution-host')
      const connectionId = hostedReviewSshConnectionId(args.executionHostId ?? 'local')
      if (typeof args.parentId === 'number') {
        const { replyBitbucketPRComment } = await import('../bitbucket/comments')
        return replyBitbucketPRComment(
          args.repoPath,
          args.prNumber,
          args.parentId,
          args.body,
          connectionId
        )
      }
      const { addBitbucketPRComment } = await import('../bitbucket/comments')
      return addBitbucketPRComment(
        args.repoPath,
        args.prNumber,
        args.body,
        connectionId,
        {},
        args.inline
      )
    }
  )

  ipcMain.handle(
    'bitbucket:replyPRComment',
    async (
      _event,
      args: {
        repoPath: string
        prNumber: number
        parentId: number
        body: string
        executionHostId?: ExecutionHostId
      }
    ) => {
      const { replyBitbucketPRComment } = await import('../bitbucket/comments')
      const { hostedReviewSshConnectionId } =
        await import('../source-control/hosted-review-execution-host')
      const connectionId = hostedReviewSshConnectionId(args.executionHostId ?? 'local')
      return replyBitbucketPRComment(
        args.repoPath,
        args.prNumber,
        args.parentId,
        args.body,
        connectionId
      )
    }
  )
}
