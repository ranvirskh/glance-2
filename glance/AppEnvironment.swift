//
//  AppEnvironment.swift
//  glance
//
//  Owns app-wide, long-lived controllers so Settings pages share one instance instead of racing duplicates.
//

import Foundation
import Observation

enum BuildFlavor {
    /// What this build calls itself in the UI, so the dev copy is never mistaken for the release app.
    nonisolated static var appName: String { isDevCopy ? "Glance 2" : "Glance" }

    /// A Debug build under a different bundle ID than the release app: gets its own storage (so it can't see or delete the release
    /// app's data) and easier face enrollment. Release builds are never dev copies, whatever their bundle ID.
    nonisolated static let isDevCopy: Bool = {
        #if DEBUG
        Bundle.main.bundleIdentifier != "com.jonathan.glance"
        #else
        false
        #endif
    }()
}

@Observable
@MainActor
final class AppEnvironment {
    let pocController = POCController()
    let faceUnlockCoordinator: FaceUnlockCoordinator
    /// Held, not just constructed — owns a repeating timer that would silently stop enforcing auto-lock if deallocated.
    let sessionAutoLocker: SessionAutoLocker
    /// Constructed here (not started) so the About page and `AppDelegate` share one instance; `AppDelegate` calls `updater.start()`.
    let updater = UpdaterController()

    /// Revealed by tapping the app icon 5 times on the About page. Plain in-memory `var` so it resets on every relaunch.
    var isDebugSectionRevealed = false

    init() {
        faceUnlockCoordinator = FaceUnlockCoordinator(pocController: pocController)
        sessionAutoLocker = SessionAutoLocker(pocController: pocController)
    }
}
