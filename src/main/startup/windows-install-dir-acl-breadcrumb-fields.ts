import type { CrashReportBreadcrumbData } from '../../shared/crash-reporting'
import { sanitizeCrashReportString } from '../../shared/crash-reporting'
import type { InstallPathClass } from './windows-install-path-class'
import {
  mergePackageAuthorityAceFacts,
  type PackageAuthorityAceFacts
} from './windows-package-authority-aces'

// Why: an unresolved S-1-15-2-<hash> derives from a package moniker, so it hints
// at installed software. Correlating the same SID across reports is exactly what
// identifies the polluting tool, which is the diagnostic value — so keep the raw
// form but cap the count and sanitize it. One key per SID because
// sanitizeCrashReportDetails re-truncates every string detail at 240 chars, and
// a real AppContainer SID is ~84, so a joined list loses the third mid-value.
export const WINDOWS_INSTALL_DIR_ACL_BREADCRUMB = 'windows_install_dir_acl'

const MAX_REPORTED_SIDS = 3
const MAX_SID_LENGTH = 200
const MAX_REASON_LENGTH = 200

export type TargetKey = 'installDir' | 'moduleFile' | 'resourceFile'

export type TargetOutcome = { facts: PackageAuthorityAceFacts } | { reason: string }

export type ProbeContext = {
  installPathClass: InstallPathClass
  windowsBuild: string
  gpuFallbackActive: boolean
  /** OS UI language tag; empty when it could not be read. */
  uiLanguage: string
  reason?: string
}

const MAX_UI_LANGUAGE_LENGTH = 35

/** BCP-47 English: the only UI language on which icacls prints the well-known package names verbatim. */
const ENGLISH_UI_LANGUAGE = /^en(?:[-_]|$)/i

export function targetFields(
  key: TargetKey,
  outcome: TargetOutcome | null
): CrashReportBreadcrumbData {
  if (!outcome) {
    return { [`${key}Reason`]: 'not-found' }
  }
  if ('reason' in outcome) {
    return { [`${key}Reason`]: sanitizeCrashReportString(outcome.reason, MAX_REASON_LENGTH) }
  }
  const { facts } = outcome
  return {
    [`${key}PackageAceCount`]: facts.packageAceCount,
    [`${key}ResolvedPackageAceCount`]: facts.resolvedPackageAceCount,
    [`${key}UnresolvedPackageSidCount`]: facts.unresolvedPackageSidCount,
    [`${key}CapabilitySidCount`]: facts.capabilitySidCount,
    [`${key}InheritedPackageAceCount`]: facts.inheritedPackageAceCount,
    [`${key}AceLineCount`]: facts.aceLineCount,
    [`${key}HasAllApplicationPackages`]: facts.hasAllApplicationPackages,
    [`${key}HasAllRestrictedAppPackages`]: facts.hasAllRestrictedAppPackages,
    [`${key}MatchesPoisonSignature`]: facts.matchesPoisonSignature
  }
}

function unresolvedSidFields(sids: string[]): CrashReportBreadcrumbData {
  return Object.fromEntries(
    sids
      .slice(0, MAX_REPORTED_SIDS)
      .map((sid, index) => [
        `unresolvedPackageSid${index}`,
        sanitizeCrashReportString(sid, MAX_SID_LENGTH)
      ])
  )
}

function rollupReason(context: ProbeContext, probedTargetCount: number): string | null {
  // Why: a rollup that measured nothing must not read like a clean install.
  const parts = [probedTargetCount === 0 ? 'all-targets-failed' : null, context.reason ?? null]
  const reason = parts.filter(Boolean).join('; ')
  return reason ? sanitizeCrashReportString(reason, MAX_REASON_LENGTH) : null
}

export function rollupFields(
  outcomes: (TargetOutcome | null)[],
  context: ProbeContext
): CrashReportBreadcrumbData {
  const facts = mergePackageAuthorityAceFacts(
    outcomes.flatMap((outcome) => (outcome && 'facts' in outcome ? [outcome.facts] : []))
  )
  const probedTargetCount = outcomes.filter((outcome) => outcome && 'facts' in outcome).length
  const reason = rollupReason(context, probedTargetCount)
  return {
    status: 'complete',
    probedTargetCount,
    // *AcrossTargets: per-target sums over probedTargetCount DACLs, so one
    // inherited ACE seen by all three targets counts three times. The SID set
    // below is deduped instead, which is why only these carry the suffix.
    packageAceCountAcrossTargets: facts.packageAceCount,
    // Why separate: icacls prints an installed package's SID as its family name,
    // so a zero packageAceCount does NOT mean the tree carries no package ACEs.
    resolvedPackageAceCountAcrossTargets: facts.resolvedPackageAceCount,
    capabilitySidCountAcrossTargets: facts.capabilitySidCount,
    inheritedPackageAceCountAcrossTargets: facts.inheritedPackageAceCount,
    explicitPackageAceCountAcrossTargets: facts.explicitPackageAceCount,
    aceLineCountAcrossTargets: facts.aceLineCount,
    outputLineCountAcrossTargets: facts.outputLineCount,
    hasAllApplicationPackages: facts.hasAllApplicationPackages,
    hasAllRestrictedAppPackages: facts.hasAllRestrictedAppPackages,
    unresolvedPackageSidCount: facts.unresolvedPackageSidCount,
    ...unresolvedSidFields(facts.unresolvedPackageSids),
    friendlyNameFallbackUsed: facts.friendlyNameFallbackUsed,
    // Why: icacls localizes the well-known package names and never prints their
    // SID form, so on non-English Windows a present grant is unreadable and
    // matchesPoisonSignature can be a false positive. False => discount it.
    // Keyed on the UI language, not on principal spelling: French/Spanish/
    // Japanese localize "ALL APPLICATION PACKAGES" while keeping BUILTIN and
    // NT AUTHORITY verbatim, so those principals cannot vouch for the names.
    wellKnownNameDetectionReliable:
      probedTargetCount > 0 &&
      ENGLISH_UI_LANGUAGE.test(context.uiLanguage) &&
      facts.englishSystemPrincipalSeen,
    uiLanguage: sanitizeCrashReportString(context.uiLanguage, MAX_UI_LANGUAGE_LENGTH),
    // Secondary: catches a mangled or empty read an English UI language still vouches for.
    englishSystemPrincipalSeen: facts.englishSystemPrincipalSeen,
    matchesPoisonSignature: probedTargetCount > 0 ? facts.matchesPoisonSignature : null,
    installPathClass: context.installPathClass,
    windowsBuild: sanitizeCrashReportString(context.windowsBuild, 60),
    // Why: an already-fallen-back launch has no GPU child at all, which changes
    // what the absence of a GPU crash means in a field report.
    gpuFallbackActiveThisLaunch: context.gpuFallbackActive,
    ...(reason ? { reason } : {})
  }
}
