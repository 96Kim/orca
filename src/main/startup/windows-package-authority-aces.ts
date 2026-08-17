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

// Why: icacls resolves both well-known package SIDs to friendly names (verified
// on Windows 11 26200: it prints "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION
// PACKAGES", never the SID), and it localizes them — so on non-English Windows
// neither regex below can fire and a present well-known grant is invisible.
// `friendlyNameFallbackUsed` records only that the English name path supplied a
// positive; the OS UI language is what says whether to trust a negative.
const ALL_APPLICATION_PACKAGES_NAME = /\ball application packages$/i
const ALL_RESTRICTED_APPLICATION_PACKAGES_NAME = /\ball restricted application packages$/i
// Why this cannot vouch for the names above: the package-authority names and
// these principals are separate localizable resources, and French/Spanish/
// Japanese Windows keeps BUILTIN and NT AUTHORITY verbatim while localizing
// "ALL APPLICATION PACKAGES". Absence proves the output was localized; presence
// proves nothing about the package names — so this stays a secondary signal that
// catches a mangled or empty read (see wellKnownNameDetectionReliable).
const ENGLISH_SYSTEM_PRINCIPAL = /(?:^|[\s(])(?:NT AUTHORITY|BUILTIN|NT SERVICE|CREATOR OWNER)[\\:]/

// Why: every AppContainer / package identity lives under this authority, but
// icacls prints the raw SID only when it CANNOT resolve it — a package installed
// on this box prints as its family name instead (PACKAGE_FAMILY_NAME below), so
// zero here means "no unresolvable package ACEs", not "no package ACEs".
const PACKAGE_SID = /^S-1-15-2-[\d-]+$/i
// `Name_<13-char publisher hash>` (e.g. Microsoft.WindowsTerminal_8wekyb3d8bbwe):
// locale-independent, and never a domain principal because it carries no
// backslash. Such an ACE is still a package grant the child token does not hold,
// so it is the second hypothesis if the unresolvable-SID one does not hold —
// recorded, never scored into matchesPoisonSignature.
const PACKAGE_FAMILY_NAME = /^[^\\/:*?"<>|\s][^\\/:*?"<>|]*_[a-z0-9]{13}$/i
/** Capability authority: proven harmless in the repro, tracked to stay distinguishable. */
const CAPABILITY_SID = /^S-1-15-3-[\d-]+$/i

// Why: the repro was cleared by an ADDITIVE (OI)(CI)(RX) grant, so only an ACE
// that actually grants on the probed object can satisfy an orphan. `(DENY)`
// grants nothing, and `(IO)` (inherit-only) applies to children rather than to
// this object — a hardened or EDR-managed box carrying either shape would
// otherwise report a still-poisoned install tree as healthy.
const NON_GRANTING_ACE_FLAGS = /\((?:DENY|IO)\)/i

/** `principal:(FLAG)(FLAG)…` where the flag run is the whole line suffix. */
const ACE_LINE = /^(.*):((?:\([^()]*\))+)\s*$/
// Why: SIDs are pure ASCII, so this survives both a failed echo-strip and an OEM
// codepage mangling the echoed path — the case that would otherwise drop the
// orphan ACE (it is line 1 when inherited) and report a poisoned box as clean.
const SID_ACE_LINE = /(?:^|[\s\\])(S-1-15-[23]-[\d-]+):((?:\([^()]*\))+)\s*$/i

export type PackageAuthorityAceFacts = {
  /** ACEs recognizable as package authority: raw S-1-15-2-* plus the well-known names. */
  packageAceCount: number
  /** Package ACEs icacls resolved to a package family name, invisible to packageAceCount. */
  resolvedPackageAceCount: number
  /** Only ACEs that grant on the probed object itself; see NON_GRANTING_ACE_FLAGS. */
  hasAllApplicationPackages: boolean
  hasAllRestrictedAppPackages: boolean
  /** Well-known package ACEs excluded from the two flags above because they deny
   *  or are inherit-only — kept visible so a field report can see they exist. */
  nonGrantingWellKnownPackageAceCount: number
  unresolvedPackageSidCount: number
  unresolvedPackageSids: string[]
  capabilitySidCount: number
  inheritedPackageAceCount: number
  explicitPackageAceCount: number
  friendlyNameFallbackUsed: boolean
  /** False => output was localized; true does NOT prove the package names were readable. */
  englishSystemPrincipalSeen: boolean
  /** Parse-health: 0 ACE lines off a real install path means a format surprise, not a clean DACL. */
  aceLineCount: number
  outputLineCount: number
  matchesPoisonSignature: boolean
}

function emptyFacts(): PackageAuthorityAceFacts {
  return {
    packageAceCount: 0,
    resolvedPackageAceCount: 0,
    hasAllApplicationPackages: false,
    hasAllRestrictedAppPackages: false,
    nonGrantingWellKnownPackageAceCount: 0,
    unresolvedPackageSidCount: 0,
    unresolvedPackageSids: [],
    capabilitySidCount: 0,
    inheritedPackageAceCount: 0,
    explicitPackageAceCount: 0,
    friendlyNameFallbackUsed: false,
    englishSystemPrincipalSeen: false,
    aceLineCount: 0,
    outputLineCount: 0,
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

type ParsedAce = { principal: string; inherited: boolean; grantsOnThisObject: boolean }

function parsedAce(principal: string, flags: string): ParsedAce {
  return {
    principal,
    inherited: /\(I\)/.test(flags),
    grantsOnThisObject: !NON_GRANTING_ACE_FLAGS.test(flags)
  }
}

function parseAceLine(line: string, target: string): ParsedAce | null {
  // SID-anchored first: it needs neither the echo-strip nor a decodable path.
  const sidMatch = SID_ACE_LINE.exec(line.trimEnd())
  if (sidMatch) {
    return parsedAce(sidMatch[1], sidMatch[2])
  }
  const match = ACE_LINE.exec(stripEchoedTarget(line.trim(), target).trim())
  if (!match) {
    return null
  }
  const principal = match[1].trim()
  if (!principal) {
    return null
  }
  return parsedAce(principal, match[2])
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
    if (PACKAGE_FAMILY_NAME.test(principal)) {
      facts.resolvedPackageAceCount += 1
    }
    return
  }
  facts.packageAceCount += 1
  if (ace.inherited) {
    facts.inheritedPackageAceCount += 1
  } else {
    facts.explicitPackageAceCount += 1
  }
  if (isWellKnownSid || isFriendlyName) {
    if (!ace.grantsOnThisObject) {
      facts.nonGrantingWellKnownPackageAceCount += 1
      return
    }
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
    if (!line.trim()) {
      continue
    }
    facts.outputLineCount += 1
    facts.englishSystemPrincipalSeen ||= ENGLISH_SYSTEM_PRINCIPAL.test(line)
    const ace = parseAceLine(line, target)
    if (ace) {
      facts.aceLineCount += 1
      applyAce(facts, ace)
    }
  }
  facts.matchesPoisonSignature =
    facts.unresolvedPackageSidCount > 0 &&
    !facts.hasAllApplicationPackages &&
    !facts.hasAllRestrictedAppPackages
  return facts
}

/** Counts sum across targets; SIDs and booleans collapse. Callers must name the
 *  summed fields so a report is not read as a single DACL. */
export function mergePackageAuthorityAceFacts(
  all: PackageAuthorityAceFacts[]
): PackageAuthorityAceFacts {
  const merged = emptyFacts()
  const seenSids = new Set<string>()
  for (const facts of all) {
    merged.packageAceCount += facts.packageAceCount
    merged.resolvedPackageAceCount += facts.resolvedPackageAceCount
    merged.capabilitySidCount += facts.capabilitySidCount
    merged.inheritedPackageAceCount += facts.inheritedPackageAceCount
    merged.explicitPackageAceCount += facts.explicitPackageAceCount
    merged.nonGrantingWellKnownPackageAceCount += facts.nonGrantingWellKnownPackageAceCount
    merged.aceLineCount += facts.aceLineCount
    merged.outputLineCount += facts.outputLineCount
    merged.hasAllApplicationPackages ||= facts.hasAllApplicationPackages
    merged.hasAllRestrictedAppPackages ||= facts.hasAllRestrictedAppPackages
    merged.friendlyNameFallbackUsed ||= facts.friendlyNameFallbackUsed
    merged.englishSystemPrincipalSeen ||= facts.englishSystemPrincipalSeen
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
