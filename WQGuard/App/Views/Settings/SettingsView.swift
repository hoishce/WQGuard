//
//  SettingsView.swift
//  WQGuard
//
//  Settings screen to manage known tool whitelist and custom exclusions.
//

import SwiftUI
import WQGuardCore

public struct SettingsView: View {
    @EnvironmentObject var vm: ScanViewModel
    @State private var showResetConfirm = false
    @State private var showBaselineClearConfirm = false

    public init() {}

    public var body: some View {
        List {
            // Built-in Known Tools Whitelist
            Section {
                ForEach(vm.whitelistedTools.filter { $0.isBuiltIn }) { tool in
                    Toggle(isOn: Binding(
                        get: { tool.isEnabled },
                        set: { vm.toggleWhitelist(for: tool, isEnabled: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(tool.name)
                                .font(.subheadline.bold())
                            Text(tool.isBuiltIn ? WQStrings.builtinWhitelistRuleDesc : tool.description)
                                .font(.caption)
                                .foregroundColor(.gray)
                        }
                    }
                }
            } header: {
                Text(WQStrings.settingsBuiltinWhitelist)
            } footer: {
                Text(WQStrings.settingsBuiltinWhitelistFooter)
            }

            // Custom Whitelist Rules
            Section {
                let customTools = vm.whitelistedTools.filter { !$0.isBuiltIn }
                if customTools.isEmpty {
                    Text(WQStrings.settingsNoCustomRules)
                        .font(.caption)
                        .foregroundColor(.gray)
                } else {
                    ForEach(customTools) { tool in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(tool.name)
                                    .font(.subheadline.bold())
                                Text(tool.allowedBundleIds.joined(separator: ", "))
                                    .font(.caption.monospaced())
                                    .foregroundColor(.gray)
                            }
                            Spacer()
                        }
                    }
                    .onDelete { indexSet in
                        for idx in indexSet {
                            let tool = customTools[idx]
                            vm.removeCustomWhitelistRule(named: tool.name)
                        }
                    }
                }

                Button(action: { vm.showAddRuleSheet = true }) {
                    Label(WQStrings.settingsAddRule, systemImage: "plus.circle.fill")
                        .foregroundColor(.teal)
                }
            } header: {
                Text(WQStrings.settingsCustomRules)
            }

            // Reset Section
            Section {
                Button(role: .destructive, action: { showResetConfirm = true }) {
                    Text(WQStrings.settingsResetButton)
                }
            }

            // Scan Baseline
            Section {
                if let baseline = vm.scanBaseline {
                    Text(WQStrings.baselineStatusEstablished(
                        date: baseline.createdAt.formatted(date: .abbreviated, time: .omitted),
                        count: baseline.entries.count
                    ))
                    .font(.caption)
                    .foregroundColor(.gray)
                } else {
                    Text(WQStrings.baselineStatusNone)
                        .font(.caption)
                        .foregroundColor(.gray)
                }

                Button(action: { vm.establishBaseline() }) {
                    Label(WQStrings.baselineSetButton, systemImage: "arrow.down.doc.fill")
                        .foregroundColor(.teal)
                }
                .disabled(vm.currentSession == nil)

                if vm.scanBaseline != nil {
                    Button(role: .destructive, action: { showBaselineClearConfirm = true }) {
                        Text(WQStrings.baselineClearButton)
                    }
                }
            } header: {
                Text(WQStrings.baselineSectionTitle)
            }

            // About WQGuard
            Section {
                HStack {
                    Text(WQStrings.settingsEngineVersion)
                    Spacer()
                    Text("WQGuardCore v1.3.4").foregroundColor(.gray)
                }
                HStack {
                    Text(WQStrings.settingsAppBuild)
                    Spacer()
                    let ver = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.3.4"
                    let bld = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "25"
                    Text("\(ver) (Build \(bld))").foregroundColor(.gray)
                }
                HStack {
                    Text(WQStrings.settingsOperatingMode)
                    Spacer()
                    Text(WQStrings.settingsReadOnlyMode).foregroundColor(.green)
                }
            } header: {
                Text(WQStrings.settingsAboutHeader)
            } footer: {
                Text(WQStrings.settingsAboutFooter)
            }
        }
        .navigationTitle(WQStrings.tabSettings)
        .sheet(isPresented: $vm.showAddRuleSheet) {
            AddWhitelistRuleSheet()
        }
        .confirmationDialog(
            WQStrings.settingsResetConfirmTitle,
            isPresented: $showResetConfirm,
            titleVisibility: .visible
        ) {
            Button(WQStrings.settingsResetConfirmAction, role: .destructive) {
                vm.resetWhitelistToDefaults()
            }
            Button(WQStrings.buttonCancel, role: .cancel) {}
        } message: {
            Text(WQStrings.settingsResetConfirmMessage)
        }
        .confirmationDialog(
            WQStrings.baselineClearConfirmTitle,
            isPresented: $showBaselineClearConfirm,
            titleVisibility: .visible
        ) {
            Button(WQStrings.baselineClearButton, role: .destructive) {
                vm.clearBaseline()
            }
            Button(WQStrings.buttonCancel, role: .cancel) {}
        } message: {
            Text(WQStrings.baselineClearConfirmMessage)
        }
    }
}
