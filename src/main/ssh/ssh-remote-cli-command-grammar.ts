/**
 * Per-command flag grammar for the SSH shim, which has no local `CommandSpec` registry.
 * Boolean flags decide whether the next token is a value; repeatable flags decide whether
 * multiple occurrences fold into one separator-joined value instead of last-value-wins.
 */
import {
  LINEAR_PROJECT_EDIT_CLEAR_FLAGS,
  LINEAR_PROJECT_EDIT_COMMAND,
  LINEAR_PROJECT_EDIT_REPEATABLE_FLAGS
} from './ssh-remote-linear-project-edit-request'

export type RemoteFlagOccurrence = { name: string; value: string | boolean }

export const REPEATED_FLAG_SEPARATOR = '\u0000'

type RemoteCommandGrammar = {
  command: readonly string[]
  booleanFlags?: readonly string[]
  repeatableFlags?: readonly string[]
}

const GLOBAL_REMOTE_BOOLEAN_FLAGS = new Set([
  'all',
  'attachments',
  'children',
  'comments',
  'current',
  'full',
  'help',
  'hide-diff',
  'inject',
  'include-archived',
  'include-visual-layouts',
  'json',
  'me',
  'relations',
  'parent-current',
  'unread',
  'updates',
  'wait'
])

const REMOTE_COMMAND_GRAMMARS: readonly RemoteCommandGrammar[] = [
  // Why: Android launch already uses `--activity <name>`; only Linear issue reads take it as a boolean.
  { command: ['linear', 'issue'], booleanFlags: ['activity'] },
  { command: ['linear', 'create'], repeatableFlags: ['label'] },
  { command: ['linear', 'save-issue'], repeatableFlags: ['label'] },
  { command: ['linear', 'label', 'add'], repeatableFlags: ['label'] },
  { command: ['linear', 'label', 'remove'], repeatableFlags: ['label'] },
  { command: ['linear', 'label', 'set'], repeatableFlags: ['label'] },
  { command: ['linear', 'project', 'create'], repeatableFlags: ['team', 'member', 'label'] },
  // Why: the clear flags must be boolean here or `--clear-lead <project>` would eat the target.
  {
    command: LINEAR_PROJECT_EDIT_COMMAND,
    booleanFlags: LINEAR_PROJECT_EDIT_CLEAR_FLAGS,
    repeatableFlags: LINEAR_PROJECT_EDIT_REPEATABLE_FLAGS
  }
]

export function isRemoteBooleanFlag(flag: string, commandPath: readonly string[]): boolean {
  return (
    GLOBAL_REMOTE_BOOLEAN_FLAGS.has(flag) ||
    matchingGrammars(commandPath).some((grammar) => grammar.booleanFlags?.includes(flag) === true)
  )
}

export function remoteRepeatableFlags(commandPath: readonly string[]): ReadonlySet<string> {
  return new Set(matchingGrammars(commandPath).flatMap((grammar) => grammar.repeatableFlags ?? []))
}

export function foldRemoteFlagOccurrences(
  commandPath: readonly string[],
  occurrences: readonly RemoteFlagOccurrence[]
): Map<string, string | boolean> {
  const repeatable = remoteRepeatableFlags(commandPath)
  const flags = new Map<string, string | boolean>()
  for (const { name, value } of occurrences) {
    const previous = flags.get(name)
    if (typeof previous === 'string' && typeof value === 'string' && repeatable.has(name)) {
      flags.set(name, `${previous}${REPEATED_FLAG_SEPARATOR}${value}`)
      continue
    }
    flags.set(name, value)
  }
  return flags
}

function matchingGrammars(commandPath: readonly string[]): RemoteCommandGrammar[] {
  return REMOTE_COMMAND_GRAMMARS.filter((grammar) =>
    grammar.command.every((part, index) => commandPath[index] === part)
  )
}
