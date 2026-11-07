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
    static var isleShowsScan: Bool { GlanceSettings.shared.showScanInIsle && isleUnderstandsUs }

    private static var isleUnderstandsUs: Bool {
        NSRunningApplication.runningApplications(withBundleIdentifier: isleBundleID).contains {
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

    // MARK: - Isle's Glance chip
    //
    // Isle asks for Glance's status and shows it in its header; its card can start the Touch ID unlock and open Settings. All
    // messages are DistributedNotificationCenter notifications, so any process can post one: Glance only answers a well-formed
    // request from "isle", shares nothing secret (state flags and a short unlock history, never the password or the face), and
    // the unlock command only raises Glance's own Touch ID prompt, which still needs the user's finger.

    static let statusNotification = "com.ranvirskh.glance2.status"
    private static let requestStatusNotification = "com.ranvirskh.glance2.requestStatus"
    private static let unlockNotification = "com.ranvirskh.glance2.unlock"
    private static let openSettingsNotification = "com.ranvirskh.glance2.openSettings"

    private static var observers: [NSObjectProtocol] = []
    private static var isEnabled: @MainActor () -> Bool = { false }

    static func startListening(isEnabled: @escaping @MainActor () -> Bool, unlock: @escaping @MainActor () -> Void, openSettings: @escaping @MainActor () -> Void) {
        self.isEnabled = isEnabled
        let center = DistributedNotificationCenter.default()
        func listen(_ name: String, _ action: @escaping @MainActor () -> Void) {
            observers.append(center.addObserver(forName: Notification.Name(name), object: nil, queue: .main) { note in
                MainActor.assumeIsolated {
                    guard (note.userInfo?["v"] as? Int) == 1, note.userInfo?["source"] as? String == "isle" else { return }
                    action()
                }
            })
        }
        listen(requestStatusNotification) { publishStatus() }
        listen(unlockNotification) { unlock() }
        listen(openSettingsNotification) { openSettings() }
        // Isle's chip should follow the lock without asking: the session locking or unlocking is the one thing it shows live.
        observers.append(NotificationCenter.default.addObserver(forName: .secureCredentialSessionDidChange, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { publishStatus() }
        })
    }

    /// Sent when asked, when the session locks or unlocks, and after each scan. Does nothing unless Isle is running and understands it.
    static func publishStatus() {
        guard isleUnderstandsUs else { return }
        let history = UnlockHistory.entries.map { ["t": $0.t, "place": $0.place, "result": $0.result, "ok": $0.ok] as [String: Any] }
        let info: [String: Any] = [
            "v": 1, "source": "glance2", "enabled": isEnabled(),
            "locked": !SecureCredentialManager.isSessionUnlocked, "hasPassword": SecureCredentialManager.hasStoredPassword(),
            "history": history,
        ]
        DistributedNotificationCenter.default().postNotificationName(
            Notification.Name(statusNotification), object: nil, userInfo: info, deliverImmediately: true)
    }
}

/// The last few scans (where, what happened, when) for Isle's Glance card. No names, passwords or faces: only a place and a result.
enum UnlockHistory {
    struct Entry: Codable { let t: Double; let place: String; let result: String; let ok: Bool }
    private static let key = "GlanceUnlockHistory"
    static let limit = 10

    static var entries: [Entry] {
        UserDefaults.standard.data(forKey: key).flatMap { try? JSONDecoder().decode([Entry].self, from: $0) } ?? []
    }

    static func record(place: String, result: String, ok: Bool, at date: Date = Date()) {
        let updated = ([Entry(t: date.timeIntervalSince1970, place: place, result: result, ok: ok)] + entries).prefix(limit)
        if let data = try? JSONEncoder().encode(Array(updated)) { UserDefaults.standard.set(data, forKey: key) }
    }
}
