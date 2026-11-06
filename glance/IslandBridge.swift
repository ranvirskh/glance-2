//
//  IslandBridge.swift
//  glance
//
//  Shows Glance's face scan in Isle (the notch app) when Isle is running, so one island does everything. Without Isle running,
//  or with the setting off, none of this does anything and Glance draws its own notch scan as before.
//
//  The message is a DistributedNotificationCenter notification Isle validates (see ExternalPopup in Isle): a single pop-up with
//  the id "scan" whose text changes as the scan goes, which Isle updates in place.
//

import AppKit

@MainActor
enum IslandBridge {
    static let isleBundleID = "local.isle.app"
    static let popupNotification = "com.ranvirskh.island.popup"

    /// Isle declares the protocol version it understands in its Info.plist; an older Isle would silently drop our messages and the
    /// user would see no scan at all, so Glance only hands the scan over to an Isle that says it can show it.
    static let integrationKey = "IslandIntegration"

    /// True when Isle is running, understands these messages, and the user hasn't switched this off: its island shows the scan,
    /// so Glance doesn't draw its own.
    static var isleShowsScan: Bool {
        guard GlanceSettings.shared.showScanInIsle else { return false }
        return NSRunningApplication.runningApplications(withBundleIdentifier: isleBundleID).contains {
            (($0.bundleURL.flatMap { Bundle(url: $0)?.infoDictionary }?[integrationKey] as? Int) ?? 0) >= 1
        }
    }

    /// The tap Glance's own notch gives on a successful unlock, which Isle's island doesn't know to give.
    static func playSuccessHaptic() {
        guard isleShowsScan, GlanceSettings.shared.hapticFeedbackEnabled else { return }
        NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
    }

    static func show(symbol: String, title: String, subtitle: String = "") {
        guard isleShowsScan else { return }
        var info: [String: Any] = ["v": 1, "source": "glance2", "id": "scan", "symbol": symbol, "title": String(title.prefix(40))]
        if !subtitle.isEmpty { info["subtitle"] = String(subtitle.prefix(80)) }
        DistributedNotificationCenter.default().postNotificationName(
            Notification.Name(popupNotification), object: nil, userInfo: info, deliverImmediately: true)
    }
}
