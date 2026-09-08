import { describe, expect, it } from 'vitest'
import { presentBitbucketPRMergeState } from './bitbucket-pr-merge-state'

describe('presentBitbucketPRMergeState', () => {
  it('returns directMergeAvailable true for open review', () => {
    const state = presentBitbucketPRMergeState({
      state: 'open',
      status: 'success',
      mergeable: 'UNKNOWN'
    })
    expect(state.directMergeAvailable).toBe(true)
    expect(state.label).toBe('Merge pull request')
  })

  it('blocks merge for conflicting review', () => {
    const state = presentBitbucketPRMergeState({
      state: 'open',
      status: 'success',
      mergeable: 'CONFLICTING'
    })
    expect(state.directMergeAvailable).toBe(false)
    expect(state.label).toBe('Merge blocked')
    expect(state.tooltip).toContain('merge conflicts')
  })

  it('handles closed review', () => {
    const state = presentBitbucketPRMergeState({
      state: 'closed',
      status: 'neutral',
      mergeable: 'UNKNOWN'
    })
    expect(state.directMergeAvailable).toBe(false)
    expect(state.label).toBe('Declined')
  })

  it('handles merged review', () => {
    const state = presentBitbucketPRMergeState({
      state: 'merged',
      status: 'success',
      mergeable: 'UNKNOWN'
    })
    expect(state.directMergeAvailable).toBe(false)
    expect(state.label).toBe('Merged')
  })
})
