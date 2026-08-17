/**
 * Parses `icacls <path>` output into package-authority (S-1-15-2-*) ACE facts.
 *
 * Why this shape matters: on Windows 11 26200 an install tree carrying an
 * S-1-15-2-<unresolvable> ACE, with neither S-1-15-2-1 nor S-1-15-2-2 present
 * to satisfy it, reproduced GPU + renderer STATUS_BREAKPOINT (0x80000003) at
 * child init 10/10 launches on stock Electron 43.1.0. Adding either well-known
 * package SID additively made it healthy with the orphan left in place. The
 * mechanism is unknown; this only records the observed DACL shape.
 */

/** Well-known: ALL APPLICATION PACKAGES. */
const ALL_APPLICATION_PACKAGES_SID = 'S-1-15-2-1'
/** Well-known: ALL RESTRICTED APPLICATION PACKAGES. */
const ALL_RESTRICTED_APPLICATION_PACKAGES_SID = 'S-1-15-2-2'

// Why: icacls resolves both well-known package SIDs to localized friendly names
// (verified on Windows 11 26200: it prints "APPLICATION PACKAGE AUTHORITY\ALL
// APPLICATION PACKAGES", never the SID), so the name form is the only signal
// available for them. `friendlyNameFallbackUsed` records when that path fired so
// a non-English field report is not silently misread as "no well-known SID".
const ALL_APPLICATION_PACKAGES_NAME = /\ball application packages$/i
const ALL_RESTRICTED_APPLICATION_PACKAGES_NAME = /\ball restricted application packages$/i

/** Package authority: every AppContainer / package identity lives here. */
const PACKAGE_SID = /^S-1-15-2-[\d-]+$/i
/** Capability authority: proven harmless in the repro, tracked to stay distinguishable. */
const CAPABILITY_SID = /^S-1-15-3-[\d-]+$/i

/** `principal:(FLAG)(FLAG)…` where the flag run is the whole line suffix. */
const ACE_LINE = /^(.*):((?:\([^()]*\))+)\s*$/

export type PackageAuthorityAceFacts = {
  packageAceCount: number
  hasAllApplicationPackages: boolean
  hasAllRestrictedAppPackages: boolean
  unresolvedPackageSidCount: number
  unresolvedPackageSids: string[]
  capabilitySidCount: number
  inheritedPackageAceCount: number
  explicitPackageAceCount: number
  friendlyNameFallbackUsed: boolean
  matchesPoisonSignature: boolean
}

function emptyFacts(): PackageAuthorityAceFacts {
  return {
    packageAceCount: 0,
    hasAllApplicationPackages: false,
    hasAllRestrictedAppPackages: false,
    unresolvedPackageSidCount: 0,
    unresolvedPackageSids: [],
    capabilitySidCount: 0,
    inheritedPackageAceCount: 0,
    explicitPackageAceCount: 0,
    friendlyNameFallbackUsed: false,
    matchesPoisonSignature: false
  }
}

/**
 * icacls prefixes the first ACE with the echoed target path and no reliable
 * separator (`C:\Program Files NT SERVICE\TrustedInstaller:(F)`), so strip the
 * path we asked about rather than guessing where the principal starts.
 */
function stripEchoedTarget(line: string, target: string): string {
  const normalized = line.replace(/\//g, '\\')
  const normalizedTarget = target.replace(/\//g, '\\')
  if (normalized.toLowerCase().startsWith(normalizedTarget.toLowerCase())) {
    return normalized.slice(normalizedTarget.length).trimStart()
  }
  return line
}

type ParsedAce = { principal: string; inherited: boolean }

function parseAceLine(line: string, target: string): ParsedAce | null {
  const match = ACE_LINE.exec(stripEchoedTarget(line.trim(), target).trim())
  if (!match) {
    return null
  }
  const principal = match[1].trim()
  if (!principal) {
    return null
  }
  return { principal, inherited: /\(I\)/.test(match[2]) }
}

function applyAce(facts: PackageAuthorityAceFacts, ace: ParsedAce): void {
  const { principal } = ace
  if (CAPABILITY_SID.test(principal)) {
    facts.capabilitySidCount += 1
    return
  }
  const isWellKnownSid =
    principal.toUpperCase() === ALL_APPLICATION_PACKAGES_SID ||
    principal.toUpperCase() === ALL_RESTRICTED_APPLICATION_PACKAGES_SID
  const isFriendlyName =
    ALL_RESTRICTED_APPLICATION_PACKAGES_NAME.test(principal) ||
    ALL_APPLICATION_PACKAGES_NAME.test(principal)
  if (!PACKAGE_SID.test(principal) && !isFriendlyName) {
    return
  }
  facts.packageAceCount += 1
  if (ace.inherited) {
    facts.inheritedPackageAceCount += 1
  } else {
    facts.explicitPackageAceCount += 1
  }
  if (isWellKnownSid || isFriendlyName) {
    // Restricted first: "ALL APPLICATION PACKAGES" is not a substring of the
    // restricted name, but keeping the order explicit documents the intent.
    if (
      principal.toUpperCase() === ALL_RESTRICTED_APPLICATION_PACKAGES_SID ||
      ALL_RESTRICTED_APPLICATION_PACKAGES_NAME.test(principal)
    ) {
      facts.hasAllRestrictedAppPackages = true
    } else {
      facts.hasAllApplicationPackages = true
    }
    if (isFriendlyName && !isWellKnownSid) {
      facts.friendlyNameFallbackUsed = true
    }
    return
  }
  // Unresolved: icacls only prints the raw SID form when it cannot map it to a name.
  facts.unresolvedPackageSidCount += 1
  facts.unresolvedPackageSids.push(principal)
}

/**
 * @param target the path passed to icacls, needed to strip its echo from line 1.
 */
export function parsePackageAuthorityAces(
  icaclsOutput: string,
  target: string
): PackageAuthorityAceFacts {
  const facts = emptyFacts()
  for (const line of icaclsOutput.split(/\r?\n/)) {
    const ace = parseAceLine(line, target)
    if (ace) {
      applyAce(facts, ace)
    }
  }
  facts.matchesPoisonSignature =
    facts.unresolvedPackageSidCount > 0 &&
    !facts.hasAllApplicationPackages &&
    !facts.hasAllRestrictedAppPackages
  return facts
}

export function mergePackageAuthorityAceFacts(
  all: PackageAuthorityAceFacts[]
): PackageAuthorityAceFacts {
  const merged = emptyFacts()
  const seenSids = new Set<string>()
  for (const facts of all) {
    merged.packageAceCount += facts.packageAceCount
    merged.capabilitySidCount += facts.capabilitySidCount
    merged.inheritedPackageAceCount += facts.inheritedPackageAceCount
    merged.explicitPackageAceCount += facts.explicitPackageAceCount
    merged.hasAllApplicationPackages ||= facts.hasAllApplicationPackages
    merged.hasAllRestrictedAppPackages ||= facts.hasAllRestrictedAppPackages
    merged.friendlyNameFallbackUsed ||= facts.friendlyNameFallbackUsed
    // Any single poisoned target is enough: the repro showed DLL-only pollution
    // killing the renderer while the directory object alone was harmless.
    merged.matchesPoisonSignature ||= facts.matchesPoisonSignature
    for (const sid of facts.unresolvedPackageSids) {
      seenSids.add(sid)
    }
  }
  merged.unresolvedPackageSids = [...seenSids]
  merged.unresolvedPackageSidCount = seenSids.size
  return merged
}
