//
//  TrustEngine.swift
//  WQGuardCore
//
//  User-trust rules for installed applications: strict, capability-bound
//  whitelist rules built from an actual scan finding. A trusted app is
//  recognised only while its bundle ID, signing team (when verified) and
//  detected capability set still match the snapshot taken at trust time;
//  any new privilege-escalation capability re-flags the app.
//

import Foundation

/// Decides whether a scan finding may be trusted by the user, and builds the
/// strict whitelist rule that represents that trust decision.
public enum TrustEngine {

    /// Brand-impersonation indicators (fake wallet / messenger repackages)
    /// can never be trusted away: they are evidence of deception, not of
    /// a legitimate tool the user installed on purpose.
    private static let impersonationSignaturePrefix = "IMPERSONATION:"

    /// Returns true only when the finding is eligible for user trust:
    /// - the engine marked the finding whitelist-eligible,
    /// - no escaping symlink was found (structurally hostile findings can
    ///   never be downgraded by any rule),
    /// - no brand-impersonation indicator is present.
    public static func canTrust(_ finding: ScanFinding) -> Bool {
        guard finding.evidence.isWhitelistEligible else { return false }
        guard finding.evidence.escapingSymlinks.isEmpty else { return false }
        guard !finding.indicators.contains(where: { $0.signature.hasPrefix(impersonationSignaturePrefix) }) else {
            return false
        }
        return true
    }

    /// Builds the strict whitelist rule that captures the user's trust
    /// decision for this exact finding, or nil when the finding cannot be
    /// trusted. The rule binds:
    /// - the bundle ID (exact),
    /// - every App Group the app currently declares (a new group later
    ///   breaks the match and re-flags the app),
    /// - the signing Team ID, but only when the engine verified it
    ///   (unverified team IDs are never used as a trust anchor),
    /// - the exact capability set observed at trust time (matched symbols
    ///   plus indicator signatures). Any new exploit primitive observed
    ///   in a later scan fails the subset check and re-flags the app.
    public static func trustRule(for finding: ScanFinding) -> WhitelistedTool? {
        guard canTrust(finding) else { return nil }

        var signatures = Set(finding.evidence.matchedSymbols)
        for indicator in finding.indicators {
            signatures.insert(indicator.signature)
        }

        let teamIds: [String]?
        if finding.evidence.isTeamIdWhitelistVerified,
           let teamId = finding.teamId,
           !teamId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            teamIds = [teamId]
        } else {
            teamIds = nil
        }

        return WhitelistedTool(
            name: finding.displayName,
            allowedBundleIds: [finding.bundleId],
            allowedAppGroups: finding.evidence.appGroups.sorted(),
            allowedTeamIds: teamIds,
            expectedSignatures: Array(signatures).sorted(),
            description: WQLocale.pick(
                en: "User-trusted app (bound to signing team and observed capabilities)",
                zh: "用户信任的应用（绑定签名团队与当前检测到的能力）"
            ),
            isEnabled: true,
            isBuiltIn: false
        )
    }
}
