//
//  SystemAuthInterceptor.swift
//  glance
//
//  Watches for Touch ID / password prompts raised by Chrome (CoreAuthUI, SecurityAgent, or a Chrome sheet),
//  hides them while the face scan runs, then flips the prompt to password mode so the stored password can be typed.
//  Opt-in (GlanceSettings.interceptSystemAuth). Only acts while Chrome has been frontmost in the last few seconds.
//

import AppKit
import ApplicationServices
import CoreGraphics
import OSLog
import ScreenCaptureKit

/// An on-screen auth prompt. AXUIElement is a CF reference that is safe to hand between threads.
struct AuthPrompt: @unchecked Sendable {
    let key: String
    let pid: pid_t
    /// Top-left-origin screen coordinates (CoreGraphics), same as `kCGWindowBounds`.
    let frame: CGRect
    /// Candidate for the off-screen move. nil for Chrome sheets (they live inside Chrome's window).
    let axWindow: AXUIElement?
    let roots: [AXUIElement]
    /// For excluding the dialog from the backdrop capture. nil for Chrome sheets (they aren't separate windows).
    var windowID: CGWindowID? = nil
}

@MainActor
final class SystemAuthInterceptor {
    var onPromptAppeared: (@MainActor (AuthPrompt) -> Void)?
    var onPromptGone: (@MainActor () -> Void)?
    /// Checked every tick so toggling the setting needs no extra wiring.
    var isAllowed: @MainActor () -> Bool = { true }
    /// When true, system prompts from any app qualify — not only ones that follow Chrome.
    var allowsAnyApp: @MainActor () -> Bool = { false }

    private(set) var currentPrompt: AuthPrompt?

    private static let chromeBundleID = "com.google.Chrome"
    private nonisolated static let systemOwners: Set<String> = ["CoreAuthUI", "SecurityAgent", "coreautha"]
    /// A system prompt only counts as Chrome-triggered if Chrome was frontmost this recently (CoreAuthUI takes focus when it appears).
    private static let chromeRecency: TimeInterval = 5

    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var lastChromeFrontAt: Date?
    private var axEnabledPIDs: Set<pid_t> = []
    private var isScanning = false
    private var missedScans = 0
    private var tickCount = 0
    private static var askedForScreenCapture = false
    private var lastGate = ""
    nonisolated private static let log = Logger(subsystem: "glance.auth", category: "interceptor")
    /// Rate-limits the "ignored" log, which would otherwise print on every 120ms tick while the dialog is up.
    nonisolated(unsafe) private static var lastIgnoredKey = ""

    private var shield: NSPanel?

    // MARK: - Lifecycle

    func start() {
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didActivateApplicationNotification,
                     NSWorkspace.didLaunchApplicationNotification,
                     NSWorkspace.didTerminateApplicationNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshTimer() }
            })
        }
        refreshTimer()
    }

    /// 120ms polling only while Chrome is running (or a prompt is up) — otherwise there is nothing to watch.
    private func refreshTimer() {
        let chromeRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: Self.chromeBundleID).isEmpty
        if chromeRunning || currentPrompt != nil || allowsAnyApp() {
            guard timer == nil else { return }
            // 80ms: the dialog is visible until the next tick notices it, so this is the length of the flash before the cover appears.
            timer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated { self?.tick() }
            }
            // Lets macOS coalesce these wakeups with other timers instead of waking the CPU for each one.
            timer?.tolerance = 0.04
        } else {
            timer?.invalidate()
            timer = nil
        }
    }

    // MARK: - Detection

    private func tick() {
        tickCount &+= 1
        let chromeApp = NSRunningApplication.runningApplications(withBundleIdentifier: Self.chromeBundleID).first
        if chromeApp?.isActive == true { lastChromeFrontAt = Date() }
        let recentChrome = lastChromeFrontAt.map { Date().timeIntervalSince($0) < Self.chromeRecency } ?? false
        // Battery: full 120ms rate only while a prompt is plausible (Chrome frontmost/just was, or one is up); otherwise ~1s.
        let anyApp = allowsAnyApp()
        guard recentChrome || currentPrompt != nil || tickCount % (anyApp ? 6 : 12) == 0 else { return }
        // Nothing to watch while the display is off.
        guard CGDisplayIsAsleep(CGMainDisplayID()) == 0 else { return }

        let allowed = isAllowed(), trusted = KeystrokeInjector.isAccessibilityTrusted()
        let gate = "allowed=\(allowed) accessibility=\(trusted)"
        if gate != lastGate { lastGate = gate; Self.log.notice("gate: \(gate, privacy: .public)") }
        guard allowed, trusted, !LockMonitor.isScreenActuallyLocked() else {
            if currentPrompt != nil { clearPrompt() }
            return
        }
        if let chromeApp { enableChromeAccessibility(chromeApp) }
        guard !isScanning else { return }
        isScanning = true
        let chromePID = chromeApp?.processIdentifier
        let chromeFront = chromeApp?.isActive ?? false
        // The accessibility-tree walk is the costly part: look for a *new* Chrome sheet every 3rd tick, but keep checking one we already track.
        let tracking = currentPrompt != nil
        let scanSheet = tickCount % 4 == 0 || tracking
        Task.detached(priority: .utility) { [weak self] in
            let found = Self.findPrompt(chromePID: chromePID, chromeFrontmost: chromeFront, chromeRecent: recentChrome, scanSheet: scanSheet, tracking: tracking, anyApp: anyApp)
            await self?.finishScan(found)
        }
    }

    private func finishScan(_ found: AuthPrompt?) {
        isScanning = false
        guard let found else {
            // The dialog is rebuilt when it switches to password mode, so a gap of a few ticks is not "gone".
            missedScans += 1
            if currentPrompt != nil, missedScans >= 3 { clearPrompt() }
            return
        }
        missedScans = 0
        guard found.key != currentPrompt?.key else { return }
        // A replacement window (mode switch) must be hidden too if the one it replaced was.
        let wasHidden = shield != nil
        if wasHidden { restoreCurrentPrompt() }
        currentPrompt = found
        if wasHidden { hideCurrentPrompt() }
        onPromptAppeared?(found)
    }

    private func clearPrompt() {
        currentPrompt = nil
        missedScans = 0
        onPromptGone?()
        refreshTimer()
    }

    /// Chromium only builds its AX tree when a client asks for it.
    private func enableChromeAccessibility(_ app: NSRunningApplication) {
        guard axEnabledPIDs.insert(app.processIdentifier).inserted else { return }
        let element = AXUIElementCreateApplication(app.processIdentifier)
        AXUIElementSetAttributeValue(element, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(element, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
    }

    private nonisolated static func findPrompt(chromePID: pid_t?, chromeFrontmost: Bool, chromeRecent: Bool, scanSheet: Bool, tracking: Bool, anyApp: Bool) -> AuthPrompt? {
        // `tracking`: a prompt already accepted stays visible to us for as long as it is on screen, however long the user takes.
        if chromeRecent || chromeFrontmost || tracking || anyApp, let prompt = findSystemPrompt(tracking: tracking, anyApp: anyApp) { return prompt }
        if chromeFrontmost, scanSheet, let chromePID { return findChromeSheet(pid: chromePID) }
        return nil
    }

    /// `tracking`: a prompt we already accepted may change its wording when it flips to password mode, so only *new* prompts must
    /// say they come from Chrome — otherwise any admin prompt from another app within seconds of using Chrome would qualify.
    private nonisolated static func findSystemPrompt(tracking: Bool, anyApp: Bool) -> AuthPrompt? {
        let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
        guard let list = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] else { return nil }
        for info in list {
            guard let owner = info[kCGWindowOwnerName as String] as? String, systemOwners.contains(owner),
                  let pid = info[kCGWindowOwnerPID as String] as? pid_t,
                  let number = info[kCGWindowNumber as String] as? Int,
                  let boundsDict = info[kCGWindowBounds as String] as? NSDictionary,
                  let frame = CGRect(dictionaryRepresentation: boundsDict),
                  frame.width > 50, frame.height > 50 else { continue }
            let windows = axWindows(of: pid)
            if !tracking, !anyApp, find(in: windows, where: { labels($0).contains { $0.contains("chrome") } }) == nil {
                let key = "\(pid)-\(number)"
                if key != lastIgnoredKey {
                    lastIgnoredKey = key
                    var seen: [String] = []
                    _ = find(in: windows) { seen.append(contentsOf: labels($0)); return false }
                    log.notice("system dialog ignored, no Chrome text. owner=\(owner, privacy: .public) windows=\(windows.count) text=\(seen.prefix(8).joined(separator: " / "), privacy: .public)")
                }
                continue
            }
            let match = windows.first { windowFrame($0).map { abs($0.minX - frame.minX) < 2 && abs($0.minY - frame.minY) < 2 } ?? false }
            return AuthPrompt(key: "\(pid)-\(number)", pid: pid, frame: frame, axWindow: match ?? windows.first, roots: windows, windowID: CGWindowID(number))
        }
        return nil
    }

    private nonisolated static func findChromeSheet(pid: pid_t) -> AuthPrompt? {
        for window in axWindows(of: pid) {
            let candidates = children(window, kAXChildrenAttribute) + children(window, "AXSheets") + [window]
            for element in candidates {
                let subrole = string(element, kAXSubroleAttribute)
                let isDialog = string(element, kAXRoleAttribute) == kAXSheetRole
                    || subrole == kAXDialogSubrole || subrole == kAXSystemDialogSubrole
                guard isDialog, containsAuthControls(element), let frame = windowFrame(element) else { continue }
                return AuthPrompt(key: "chrome-\(pid)", pid: pid, frame: frame, axWindow: nil, roots: [element])
            }
        }
        return nil
    }

    // MARK: - Hide / restore

    /// Idempotent. The dialog stays exactly where macOS put it; a cover on top hides it (macOS won't let us move or reorder it).
    func hideCurrentPrompt() {
        guard let prompt = currentPrompt, shield == nil else { return }
        showShield(over: prompt.frame, windowID: prompt.windowID)
    }

    /// Drops the cover. Safe to call when nothing is hidden.
    func restoreCurrentPrompt() {
        guard let panel = shield else { return }
        shield = nil
        // Fades out instead of popping, so the cover leaves the way the notch animation does.
        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.18
            panel.animator().alphaValue = 0
        }, completionHandler: { panel.orderOut(nil) })
    }

    func waitUntilGone(timeout: Duration) async {
        let deadline = ContinuousClock.now + timeout
        while currentPrompt != nil, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Extra margin so the dialog's drop shadow, which isn't part of its window bounds, is covered too.
    private static let shieldPadding: CGFloat = 40

    private func showShield(over dialogFrame: CGRect, windowID: CGWindowID?) {
        guard let primary = NSScreen.screens.first else { return }
        let cgFrame = dialogFrame.insetBy(dx: -Self.shieldPadding, dy: -Self.shieldPadding)
        // CG is top-left origin, AppKit bottom-left; both are relative to the primary display.
        let frame = CGRect(x: cgFrame.minX, y: primary.frame.height - cgFrame.maxY, width: cgFrame.width, height: cgFrame.height)
        let panel = NSPanel(contentRect: frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.level = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.maximumWindow)))
        panel.ignoresMouseEvents = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .fullScreenAuxiliary]
        let blur = NSVisualEffectView(frame: NSRect(origin: .zero, size: frame.size))
        blur.material = .hudWindow
        blur.blendingMode = .behindWindow
        blur.state = .active
        blur.wantsLayer = true
        // Blur alone leaves the dialog's text faintly legible; the dark tint finishes the masking.
        blur.layer?.backgroundColor = NSColor.black.withAlphaComponent(0.7).cgColor
        blur.layer?.cornerRadius = 12
        panel.contentView = blur
        panel.orderFrontRegardless()
        shield = panel

        // The blur covers the dialog immediately; once a clean backdrop is captured it is swapped for the "nothing there" look.
        Task { [weak self, weak panel] in
            guard let image = await Self.captureBackdrop(of: cgFrame, excluding: windowID),
                  let self, let panel, self.shield === panel else { return }
            // Crossfaded over the blur rather than swapped in, so the cover doesn't visibly jump from dark to the page.
            let view = NSImageView(frame: NSRect(origin: .zero, size: frame.size))
            view.image = image
            view.imageScaling = .scaleAxesIndependently
            view.alphaValue = 0
            panel.contentView?.addSubview(view)
            NSAnimationContext.runAnimationGroup({ context in
                context.duration = 0.12
                view.animator().alphaValue = 1
            }, completionHandler: nil)
        }
    }

    /// A picture of the screen region with the dialog and Glance's own windows left out. Returns nil (caller keeps the blur) unless
    /// Screen Recording is granted AND the dialog was found and excluded — otherwise the picture would show the dialog itself.
    private static func captureBackdrop(of frame: CGRect, excluding windowID: CGWindowID?) async -> NSImage? {
        guard let windowID else { return nil }
        guard CGPreflightScreenCaptureAccess() else {
            // Once per launch: asking on every prompt kept putting a system alert next to the dialog.
            if !askedForScreenCapture { askedForScreenCapture = true; _ = CGRequestScreenCaptureAccess() }
            return nil
        }
        guard let content = try? await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true),
              let display = content.displays.first(where: { $0.frame.intersects(frame) }),
              content.windows.contains(where: { $0.windowID == windowID }) else { return nil }
        let mine = Bundle.main.bundleIdentifier
        let excluded = content.windows.filter { $0.windowID == windowID || $0.owningApplication?.bundleIdentifier == mine }
        let filter = SCContentFilter(display: display, excludingWindows: excluded)
        let config = SCStreamConfiguration()
        config.sourceRect = frame.offsetBy(dx: -display.frame.minX, dy: -display.frame.minY)
        let scale = CGFloat(filter.pointPixelScale)
        config.width = Int(frame.width * scale)
        config.height = Int(frame.height * scale)
        config.showsCursor = false
        guard let image = try? await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config) else { return nil }
        return NSImage(cgImage: image, size: frame.size)
    }

    // MARK: - Password mode

    /// Presses "Use Password…" if needed, waits for the secure field, focuses it, and checks the system really focused it.
    /// Returns false (nothing typed) unless the next keystrokes will land in that field.
    func prepareForPassword(timeout: Duration = .seconds(7)) async -> Bool {
        let deadline = ContinuousClock.now + timeout
        var pressed = false
        // Re-reads `currentPrompt` each pass: pressing the button can replace the window.
        while ContinuousClock.now < deadline, let prompt = currentPrompt {
            let step = await Task.detached { Self.passwordStep(prompt, press: !pressed) }.value
            if step.focused { return true }
            pressed = pressed || step.pressed
            try? await Task.sleep(for: .milliseconds(20))
        }
        return false
    }

    private nonisolated static func passwordStep(_ prompt: AuthPrompt, press: Bool) -> (focused: Bool, pressed: Bool) {
        // System prompts rebuild their window tree when switching modes, so re-read it each time.
        let roots = prompt.axWindow != nil ? axWindows(of: prompt.pid) : prompt.roots
        if let field = find(in: roots, where: isSecureField) {
            AXUIElementSetAttributeValue(field, kAXFocusedAttribute as CFString, kCFBooleanTrue)
            let focused = focusedElement().map { CFEqual($0, field) } ?? false
            return (focused, false)
        }
        if press, let button = find(in: roots, where: isPasswordButton) {
            AXUIElementPerformAction(button, kAXPressAction as CFString)
            return (false, true)
        }
        return (false, false)
    }

    // MARK: - AX helpers

    private nonisolated static func axWindows(of pid: pid_t) -> [AXUIElement] {
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(app, 0.25)
        return children(app, kAXWindowsAttribute)
    }

    private nonisolated static func focusedElement() -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(AXUIElementCreateSystemWide(), kAXFocusedUIElementAttribute as CFString, &value) == .success,
              let value, CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
        return (value as! AXUIElement)
    }

    private nonisolated static func string(_ element: AXUIElement, _ attribute: String) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success else { return nil }
        return value as? String
    }

    private nonisolated static func children(_ element: AXUIElement, _ attribute: String) -> [AXUIElement] {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success else { return [] }
        return value as? [AXUIElement] ?? []
    }

    private nonisolated static func windowFrame(_ element: AXUIElement) -> CGRect? {
        var posRef: CFTypeRef?, sizeRef: CFTypeRef?
        var origin = CGPoint.zero, size = CGSize.zero
        guard AXUIElementCopyAttributeValue(element, kAXPositionAttribute as CFString, &posRef) == .success,
              AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &sizeRef) == .success,
              let posRef, let sizeRef,
              AXValueGetValue(posRef as! AXValue, .cgPoint, &origin),
              AXValueGetValue(sizeRef as! AXValue, .cgSize, &size) else { return nil }
        return CGRect(origin: origin, size: size)
    }

    /// Lowercased, with Apple's typographic ellipsis/apostrophe folded to ASCII so "Use Password…" matches "use password...".
    private nonisolated static func normalized(_ text: String) -> String {
        text.lowercased().replacingOccurrences(of: "…", with: "...").replacingOccurrences(of: "’", with: "'")
    }

    private nonisolated static func labels(_ element: AXUIElement) -> [String] {
        [kAXTitleAttribute, kAXDescriptionAttribute, kAXIdentifierAttribute, kAXValueAttribute]
            .compactMap { string(element, $0) }.map(normalized)
    }

    private nonisolated static func isSecureField(_ element: AXUIElement) -> Bool {
        string(element, kAXSubroleAttribute) == kAXSecureTextFieldSubrole
    }

    private nonisolated static func isPasswordButton(_ element: AXUIElement) -> Bool {
        guard string(element, kAXRoleAttribute) == kAXButtonRole else { return false }
        return labels(element).contains { $0.contains("password") && !$0.contains("forgot") }
    }

    /// Wording only, never a bare secure field: Chrome's own save-password dialogs contain one, and they are not Touch ID prompts.
    private nonisolated static func containsAuthControls(_ root: AXUIElement) -> Bool {
        find(in: [root]) { element in
            labels(element).contains { label in
                ["touch id", "use password", "enter password", "verify it"].contains { label.contains($0) }
            }
        } != nil
    }

    /// True while the system's keyboard focus is a secure text field. Used as the last check before typing the password.
    nonisolated static func isSecureFieldFocused() -> Bool {
        focusedElement().map(isSecureField) ?? false
    }

    /// Depth-limited DFS. Skips web content: Chrome pages are huge, and a site's own password field must never match.
    private nonisolated static func find(in roots: [AXUIElement], maxDepth: Int = 8, where match: (AXUIElement) -> Bool) -> AXUIElement? {
        func walk(_ element: AXUIElement, _ depth: Int) -> AXUIElement? {
            if match(element) { return element }
            guard depth < maxDepth, string(element, kAXRoleAttribute) != "AXWebArea" else { return nil }
            for child in children(element, kAXChildrenAttribute) {
                if let hit = walk(child, depth + 1) { return hit }
            }
            return nil
        }
        for root in roots { if let hit = walk(root, 0) { return hit } }
        return nil
    }
}
