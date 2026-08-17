/** Coarse install-location class for crash breadcrumbs — never the literal path. */
export type InstallPathClass =
  | 'localappdata-programs'
  | 'program-files'
  | 'program-files-x86'
  | 'appdata-roaming'
  | 'other'

function normalizeDir(value: string | undefined): string | null {
  const trimmed = value?.trim()
  return trimmed
    ? trimmed
        .replace(/[\\/]+$/, '')
        .replace(/\//g, '\\')
        .toLowerCase()
    : null
}

export function classifyInstallPath(
  installDir: string,
  env: NodeJS.ProcessEnv = process.env
): InstallPathClass {
  const target = normalizeDir(installDir)
  if (!target) {
    return 'other'
  }
  const localAppData = normalizeDir(env.LOCALAPPDATA)
  const candidates: [string | null, InstallPathClass][] = [
    [localAppData ? `${localAppData}\\programs` : null, 'localappdata-programs'],
    [normalizeDir(env['ProgramFiles(x86)']), 'program-files-x86'],
    [normalizeDir(env.ProgramW6432 ?? env.ProgramFiles), 'program-files'],
    [normalizeDir(env.APPDATA), 'appdata-roaming']
  ]
  for (const [root, klass] of candidates) {
    if (root && (target === root || target.startsWith(`${root}\\`))) {
      return klass
    }
  }
  return 'other'
}
