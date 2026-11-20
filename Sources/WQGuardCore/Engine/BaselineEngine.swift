//
//  BaselineEngine.swift
//  WQGuardCore
//
//  Scan baseline: a snapshot of the installed-app risk posture taken after
//  a full scan. Later scans are diffed against it so only genuinely new
//  risks are surfaced: newly installed apps carrying risk features, apps
//  whose risk tier escalated, and apps whose capability fingerprint
//  changed. User-trusted (whitelisted) apps never count as new risk.
//

import Foundation

/// One installed app as recorded in a scan baseline.
public struct BaselineEntry: Codable, Sendable, Equatable {
    public let bundleId: String
    public let displayName: String
    public let version: String
    public let teamId: String?
    public let riskTier: RiskTier
    /// Stable fingerprint of the risk-relevant capability set: sorted matched
    /// symbols + sorted App Groups + team ID + install channel. Version is
    /// deliberately excluded so a plain version bump is not an alert.
    public let capabilityFingerprint: String
    public let installChannel: InstallChannel

    public init(
        bundleId: String,
        displayName: String,
        version: String,
        teamId: String? = nil,
        riskTier: RiskTier,
        capabilityFingerprint: String,
        installChannel: InstallChannel
    ) {
        self.bundleId = bundleId
        self.displayName = displayName
        self.version = version
        self.teamId = teamId
        self.riskTier = riskTier
        self.capabilityFingerprint = capabilityFingerprint
        self.installChannel = installChannel
    }
}

/// A saved snapshot of a full installed-app scan.
public struct ScanBaseline: Codable, Sendable, Equatable {
    public static let currentFormatVersion = 1
    public let formatVersion: Int
    public let createdAt: Date
    /// Baseline entries keyed by bundle ID.
    public let entries: [String: BaselineEntry]

    public init(
        formatVersion: Int = ScanBaseline.currentFormatVersion,
        createdAt: Date = Date(),
        entries: [String: BaselineEntry]
    ) {
        self.formatVersion = formatVersion
        self.createdAt = createdAt
        self.entries = entries
    }
}

/// One app whose risk changed since the baseline.
public struct BaselineChange: Sendable, Equatable {
    public let finding: ScanFinding
    public let baselineEntry: BaselineEntry

    public init(finding: ScanFinding, baselineEntry: BaselineEntry) {
        self.finding = finding
        self.baselineEntry = baselineEntry
    }
}

/// Result of diffing a fresh scan against the stored baseline.
public struct BaselineDiff: Sendable, Equatable {
    /// Apps absent from the baseline that carry risk features.
    public let newRisky: [ScanFinding]
    /// Apps whose risk tier escalated since the baseline (including apps
    /// that were trusted at baseline time but no longer match any trust
    /// rule and are risky again).
    public let escalated: [BaselineChange]
    /// Apps whose capability fingerprint changed without a tier change.
    public let modified: [BaselineChange]

    public init(newRisky: [ScanFinding], escalated: [BaselineChange], modified: [BaselineChange]) {
        self.newRisky = newRisky
        self.escalated = escalated
        self.modified = modified
    }

    public var hasNewRisk: Bool {
        !newRisky.isEmpty || !escalated.isEmpty || !modified.isEmpty
    }

    public var newRiskCount: Int {
        newRisky.count + escalated.count + modified.count
    }

    /// Bundle IDs of every finding counted as new risk (for list filtering).
    public var newRiskBundleIds: Set<String> {
        var ids = Set(newRisky.map { $0.bundleId })
        ids.formUnion(escalated.map { $0.finding.bundleId })
        ids.formUnion(modified.map { $0.finding.bundleId })
        return ids
    }
}

/// Pure baseline construction and diffing. No I/O, no singletons.
public enum BaselineEngine {

    /// Deterministic fingerprint of a finding's risk-relevant capabilities.
    public static func fingerprint(for finding: ScanFinding) -> String {
        let symbols = finding.evidence.matchedSymbols.sorted().joined(separator: "\n")
        let groups = finding.evidence.appGroups.sorted().joined(separator: "\n")
        return [symbols, groups, finding.teamId ?? "", finding.installChannel.rawValue]
            .joined(separator: "\u{1F}")
    }

    /// Builds a baseline snapshot from a full scan's findings.
    public static func build(from findings: [ScanFinding], at date: Date = Date()) -> ScanBaseline {
        var entries: [String: BaselineEntry] = [:]
        for finding in findings {
            entries[finding.bundleId] = BaselineEntry(
                bundleId: finding.bundleId,
                displayName: finding.displayName,
                version: finding.version,
                teamId: finding.teamId,
                riskTier: finding.riskTier,
                capabilityFingerprint: fingerprint(for: finding),
                installChannel: finding.installChannel
            )
        }
        return ScanBaseline(createdAt: date, entries: entries)
    }

    /// Diffs a fresh scan against the stored baseline.
    public static func diff(baseline: ScanBaseline, current findings: [ScanFinding]) -> BaselineDiff {
        var newRisky: [ScanFinding] = []
        var escalated: [BaselineChange] = []
        var modified: [BaselineChange] = []

        for finding in findings {
            // User-trusted apps never count as new risk.
            if finding.isWhitelisted { continue }

            guard let entry = baseline.entries[finding.bundleId] else {
                if finding.riskTier == .highRisk || finding.riskTier == .caution {
                    newRisky.append(finding)
                }
                continue
            }

            // Trust broken: the app was trusted at baseline time but no
            // longer matches any trust rule and is risky again.
            if entry.riskTier == .knownTool {
                if finding.riskTier == .highRisk || finding.riskTier == .caution {
                    escalated.append(BaselineChange(finding: finding, baselineEntry: entry))
                }
                continue
            }

            let currentRank = finding.riskTier.severityRank
            let baselineRank = entry.riskTier.severityRank
            if currentRank > baselineRank {
                escalated.append(BaselineChange(finding: finding, baselineEntry: entry))
            } else if currentRank == baselineRank,
                      fingerprint(for: finding) != entry.capabilityFingerprint {
                modified.append(BaselineChange(finding: finding, baselineEntry: entry))
            }
            // A lower rank is an improvement, not a risk: no alert.
        }

        return BaselineDiff(newRisky: newRisky, escalated: escalated, modified: modified)
    }
}
