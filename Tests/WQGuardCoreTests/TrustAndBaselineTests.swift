//
//  TrustAndBaselineTests.swift
//  WQGuardCoreTests
//
//  Unit tests for user-trust rules (TrustEngine) and scan baselines
//  (BaselineEngine): strict capability binding, capability-change
//  re-flagging, and change-only baseline diffs.
//

import XCTest
@testable import WQGuardCore

final class TrustAndBaselineTests: XCTestCase {

    // MARK: - Finding builders

    private func erosionLikeFinding(
        riskTier: RiskTier = .caution,
        isWhitelisted: Bool = false,
        version: String = "1.0.3",
        matchedSymbols: [String] = ["container_query_create", "libsystem_containermanager.dylib"],
        appGroups: [String] = ["group.com.jbdotparty.Erosion.WQ"],
        teamId: String? = "ABCDE12345",
        teamVerified: Bool = true,
        whitelistEligible: Bool = true,
        escapingSymlinks: [String] = [],
        indicators: [ThreatIndicator]? = nil
    ) -> ScanFinding {
        let defaultIndicators = [
            ThreatIndicator(
                signature: "container_query_create",
                description: "Private symbol",
                category: ThreatIndicator.Category.privateSymbol,
                location: "__LINKEDIT",
                severity: .caution
            )
        ]
        return ScanFinding(
            bundleId: "com.jbdotparty.Erosion",
            displayName: "Erosion",
            version: version,
            teamId: teamId,
            executablePath: "/var/containers/Bundle/Application/UUID/Erosion.app/Erosion",
            bundlePath: "/var/containers/Bundle/Application/UUID/Erosion.app",
            installChannel: .developerSideloaded,
            riskTier: riskTier,
            isWhitelisted: isWhitelisted,
            whitelistedToolName: isWhitelisted ? "Erosion" : nil,
            indicators: indicators ?? defaultIndicators,
            evidence: AuditEvidence(
                matchedSymbols: matchedSymbols,
                linkedDylibs: ["libsystem_containermanager.dylib"],
                hasAppGroups: !appGroups.isEmpty,
                appGroups: appGroups,
                installChannel: .developerSideloaded,
                cryptid: 0,
                isFairPlayEncrypted: false,
                escapingSymlinks: escapingSymlinks,
                dynamicLoadingPresent: true,
                pathEnumerationPresent: false,
                remediationGuidance: "Review source before trusting.",
                isWhitelistEligible: whitelistEligible,
                isTeamIdWhitelistVerified: teamVerified
            ),
            scanTimestamp: Date(timeIntervalSince1970: 1700000000)
        )
    }

    private func safeFinding(bundleId: String = "com.example.calculator", displayName: String = "Calculator") -> ScanFinding {
        ScanFinding(
            bundleId: bundleId,
            displayName: displayName,
            version: "1.0",
            bundlePath: "/Applications/Calculator.app",
            installChannel: .appStore,
            riskTier: .safe,
            evidence: .empty(channel: .appStore)
        )
    }

    // MARK: - TrustEngine.canTrust

    func testCanTrustNormalCautionFinding() {
        XCTAssertTrue(TrustEngine.canTrust(erosionLikeFinding()))
    }

    func testCannotTrustFindingWithEscapingSymlink() {
        let finding = erosionLikeFinding(escapingSymlinks: ["/var/mobile/Containers/Data/Application/VICTIM"])
        XCTAssertFalse(TrustEngine.canTrust(finding))
    }

    func testCannotTrustWhitelistIneligibleFinding() {
        let finding = erosionLikeFinding(whitelistEligible: false)
        XCTAssertFalse(TrustEngine.canTrust(finding))
    }

    func testCannotTrustBrandImpersonationFinding() {
        let impersonation = ThreatIndicator(
            signature: "IMPERSONATION:MetaMask",
            description: "Sideloaded package impersonates MetaMask",
            category: "brand_impersonation",
            location: "CFBundleIdentifier",
            severity: .highRisk
        )
        let finding = erosionLikeFinding(riskTier: .highRisk, indicators: [impersonation])
        XCTAssertFalse(TrustEngine.canTrust(finding))
        XCTAssertNil(TrustEngine.trustRule(for: finding))
    }

    // MARK: - TrustEngine.trustRule binding

    func testTrustRuleBindsIdentityAndCapabilities() {
        let finding = erosionLikeFinding()
        let rule = TrustEngine.trustRule(for: finding)
        XCTAssertNotNil(rule)
        XCTAssertEqual(rule?.name, "Erosion")
        XCTAssertEqual(rule?.allowedBundleIds, ["com.jbdotparty.Erosion"])
        XCTAssertEqual(rule?.allowedAppGroups, ["group.com.jbdotparty.Erosion.WQ"])
        XCTAssertEqual(rule?.allowedTeamIds, ["ABCDE12345"])
        XCTAssertTrue(rule?.expectedSignatures.contains("container_query_create") ?? false)
        XCTAssertTrue(rule?.expectedSignatures.contains("libsystem_containermanager.dylib") ?? false)
        XCTAssertEqual(rule?.isBuiltIn, false)
        XCTAssertEqual(rule?.isEnabled, true)
    }

    func testTrustRuleRoundTripMatchesSameFinding() {
        let finding = erosionLikeFinding()
        let engine = WhitelistEngine()
        guard let rule = TrustEngine.trustRule(for: finding) else {
            XCTFail("Expected a trust rule for the test finding")
            return
        }
        engine.registerCustomTool(rule)

        let result = engine.isWhitelisted(
            bundleId: finding.bundleId,
            appGroups: finding.evidence.appGroups,
            matchedSignatures: finding.evidence.matchedSymbols,
            teamId: finding.teamId
        )
        XCTAssertTrue(result.isWhitelisted)
        XCTAssertEqual(result.toolName, "Erosion")
    }

    func testTrustRuleRejectsNewCapability() {
        // The app gains a new exploit primitive after being trusted:
        // the strict signature subset check must fail and re-flag it.
        let finding = erosionLikeFinding()
        let engine = WhitelistEngine()
        guard let rule = TrustEngine.trustRule(for: finding) else {
            XCTFail("Expected a trust rule for the test finding")
            return
        }
        engine.registerCustomTool(rule)

        let result = engine.isWhitelisted(
            bundleId: finding.bundleId,
            appGroups: finding.evidence.appGroups,
            matchedSignatures: finding.evidence.matchedSymbols + ["fsgetpath"],
            teamId: finding.teamId
        )
        XCTAssertFalse(result.isWhitelisted)
    }

    func testTrustRuleRejectsDifferentSigningTeam() {
        let finding = erosionLikeFinding()
        let engine = WhitelistEngine()
        guard let rule = TrustEngine.trustRule(for: finding) else {
            XCTFail("Expected a trust rule for the test finding")
            return
        }
        engine.registerCustomTool(rule)

        let result = engine.isWhitelisted(
            bundleId: finding.bundleId,
            appGroups: finding.evidence.appGroups,
            matchedSignatures: finding.evidence.matchedSymbols,
            teamId: "OTHERTEAM99"
        )
        XCTAssertFalse(result.isWhitelisted)
    }

    func testTrustRuleRejectsNewAppGroup() {
        // The app declares an additional App Group later: the rule's
        // all-groups-must-match check must fail and re-flag it.
        let finding = erosionLikeFinding()
        let engine = WhitelistEngine()
        guard let rule = TrustEngine.trustRule(for: finding) else {
            XCTFail("Expected a trust rule for the test finding")
            return
        }
        engine.registerCustomTool(rule)

        let result = engine.isWhitelisted(
            bundleId: finding.bundleId,
            appGroups: finding.evidence.appGroups + ["group.io.metamask"],
            matchedSignatures: finding.evidence.matchedSymbols,
            teamId: finding.teamId
        )
        XCTAssertFalse(result.isWhitelisted)
    }

    func testTrustRuleDoesNotBindUnverifiedTeam() {
        let finding = erosionLikeFinding(teamVerified: false)
        let rule = TrustEngine.trustRule(for: finding)
        XCTAssertNotNil(rule)
        XCTAssertNil(rule?.allowedTeamIds)
    }

    // MARK: - BaselineEngine

    func testBaselineDiffIdenticalScanHasNoNewRisk() {
        let findings = [safeFinding(), erosionLikeFinding()]
        let baseline = BaselineEngine.build(from: findings, at: Date(timeIntervalSince1970: 1700000000))
        let diff = BaselineEngine.diff(baseline: baseline, current: findings)
        XCTAssertFalse(diff.hasNewRisk)
        XCTAssertEqual(diff.newRiskCount, 0)
    }

    func testBaselineDiffDetectsNewRiskyAppButIgnoresNewSafeApp() {
        let baseline = BaselineEngine.build(from: [safeFinding(), erosionLikeFinding()])
        let newRiskyCopy = ScanFinding(
            bundleId: "com.evil.drainer",
            displayName: "Drainer",
            version: "1.0",
            bundlePath: "/Applications/Drainer.app",
            installChannel: .developerSideloaded,
            riskTier: .highRisk,
            indicators: [
                ThreatIndicator(
                    signature: "container_query_create",
                    description: "Private symbol",
                    category: ThreatIndicator.Category.privateSymbol,
                    location: "__LINKEDIT",
                    severity: .highRisk
                )
            ],
            evidence: AuditEvidence(matchedSymbols: ["container_query_create"])
        )
        let diff = BaselineEngine.diff(
            baseline: baseline,
            current: [safeFinding(), erosionLikeFinding(), newRiskyCopy, safeFinding(bundleId: "com.example.notes", displayName: "Notes")]
        )
        XCTAssertTrue(diff.hasNewRisk)
        XCTAssertEqual(diff.newRisky.map { $0.bundleId }, ["com.evil.drainer"])
        XCTAssertTrue(diff.escalated.isEmpty)
        XCTAssertTrue(diff.modified.isEmpty)
    }

    func testBaselineDiffDetectsEscalation() {
        let baseline = BaselineEngine.build(from: [erosionLikeFinding(riskTier: .caution)])
        let escalated = erosionLikeFinding(riskTier: .highRisk)
        let diff = BaselineEngine.diff(baseline: baseline, current: [escalated])
        XCTAssertTrue(diff.hasNewRisk)
        XCTAssertEqual(diff.escalated.count, 1)
        XCTAssertEqual(diff.escalated.first?.finding.bundleId, "com.jbdotparty.Erosion")
        XCTAssertEqual(diff.escalated.first?.baselineEntry.riskTier, .caution)
    }

    func testBaselineDiffDetectsCapabilityChangeWithoutTierChange() {
        let baseline = BaselineEngine.build(from: [erosionLikeFinding()])
        let changed = erosionLikeFinding(matchedSymbols: ["container_query_create", "libsystem_containermanager.dylib", "fsgetpath"])
        let diff = BaselineEngine.diff(baseline: baseline, current: [changed])
        XCTAssertTrue(diff.hasNewRisk)
        XCTAssertEqual(diff.modified.count, 1)
        XCTAssertTrue(diff.escalated.isEmpty)
    }

    func testBaselineDiffIgnoresWhitelistedFindings() {
        let baseline = BaselineEngine.build(from: [erosionLikeFinding(riskTier: .caution)])
        let trusted = erosionLikeFinding(riskTier: .knownTool, isWhitelisted: true)
        let diff = BaselineEngine.diff(baseline: baseline, current: [trusted])
        XCTAssertFalse(diff.hasNewRisk)
    }

    func testBaselineDiffIgnoresVersionOnlyChange() {
        let baseline = BaselineEngine.build(from: [erosionLikeFinding(version: "1.0.3")])
        let updated = erosionLikeFinding(version: "1.0.4")
        let diff = BaselineEngine.diff(baseline: baseline, current: [updated])
        XCTAssertFalse(diff.hasNewRisk)
    }

    func testBaselineDiffDetectsBrokenTrust() {
        // App was trusted at baseline time; it no longer matches any trust
        // rule and is risky again: that must surface as an escalation.
        let trustedAtBaseline = erosionLikeFinding(riskTier: .knownTool, isWhitelisted: true)
        let baseline = BaselineEngine.build(from: [trustedAtBaseline])
        let nowRisky = erosionLikeFinding(riskTier: .caution, isWhitelisted: false)
        let diff = BaselineEngine.diff(baseline: baseline, current: [nowRisky])
        XCTAssertTrue(diff.hasNewRisk)
        XCTAssertEqual(diff.escalated.count, 1)
    }

    func testBaselineCodableRoundTrip() throws {
        let baseline = BaselineEngine.build(
            from: [safeFinding(), erosionLikeFinding()],
            at: Date(timeIntervalSince1970: 1700000000)
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(baseline)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(ScanBaseline.self, from: data)
        XCTAssertEqual(decoded, baseline)
        XCTAssertEqual(decoded.entries.count, 2)
        XCTAssertEqual(decoded.formatVersion, ScanBaseline.currentFormatVersion)
    }

    func testBaselineFingerprintIgnoresVersionButNotCapabilities() {
        let a = erosionLikeFinding(version: "1.0.3")
        let b = erosionLikeFinding(version: "9.9.9")
        XCTAssertEqual(BaselineEngine.fingerprint(for: a), BaselineEngine.fingerprint(for: b))
        let c = erosionLikeFinding(appGroups: ["group.com.jbdotparty.Erosion.WQ", "group.other.app"])
        XCTAssertNotEqual(BaselineEngine.fingerprint(for: a), BaselineEngine.fingerprint(for: c))
    }
}
