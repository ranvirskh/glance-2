//
//  SystemAuthInterceptor.swift
//  glance
//
//  Watches for Touch ID / password prompts (system dialogs, or sheets inside an app such as Safari's AutoFill or Chrome's), lets the
//  coordinator scan the face while the normal prompt stays visible, then flips the prompt to password mode and types the stored
//  password. Chrome-only unless GlanceSettings.interceptAnyPasswordPrompt is on.
//

import AppKit
import ApplicationServices
import CoreGraphics
import OSLog

/// An on-screen auth prompt. AXUIElement is a CF reference that is safe to hand between threads.
struct AuthPrompt: @unchecked Sendable {
    let key: String
    let pid: pid_t
    /// Top-left-origin screen coordinates (CoreGraphics), same as `kCGWindowBounds`.
    let frame: CGRect
    /// Candidate for the off-screen move. nil for Chrome sheets (they live inside Chrome's window).
    let axWindow: AXUIElement?
    let roots: [AXUIElement]
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
    private var boostUntil = Date.distantPast
    private var timerInterval: TimeInterval = 0
    private var axObserver: AXObserver?
    private var observedPID: pid_t = 0
    private var lastGate = ""
    nonisolated private static let log = Logger(subsystem: "glance.auth", category: "interceptor")
    /// Rate-limits the "ignored" log, which would otherwise print on every 120ms tick while the dialog is up.
    nonisolated(unsafe) private static var lastIgnoredKey = ""

    // MARK: - Lifecycle

    func start() {
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didActivateApplicationNotification,
                     NSWorkspace.didLaunchApplicationNotification,
                     NSWorkspace.didTerminateApplicationNotification] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                MainActor.assumeIsolated {
                    // A system prompt usually brings its app to the front, so after any app switch check at full rate for a moment.
                    if note.name == NSWorkspace.didActivateApplicationNotification {
                        self?.boostUntil = Date().addingTimeInterval(3)
                        let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
                        self?.observeSheets(of: app?.processIdentifier)
                    }
                    self?.refreshTimer()
                }
            })
        }
        observeSheets(of: NSWorkspace.shared.frontmostApplication?.processIdentifier)
        refreshTimer()
    }

    /// In any-app mode, asks the app in front to tell us the moment it opens a sheet or window, so an auth sheet (Safari's AutoFill
    /// one, say) is covered right away instead of waiting for the next poll. Event-driven, so it costs nothing while nothing happens.
    private func observeSheets(of pid: pid_t?) {
        guard allowsAnyApp(), let pid, pid != observedPID, pid != ProcessInfo.processInfo.processIdentifier else { return }
        if let old = axObserver { CFRunLoopRemoveSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(old), .defaultMode) }
        axObserver = nil
        observedPID = pid

        let callback: AXObserverCallback = { _, _, _, refcon in
            guard let refcon else { return }
            let me = Unmanaged<SystemAuthInterceptor>.fromOpaque(refcon).takeUnretainedValue()
            MainActor.assumeIsolated {
                me.boostUntil = Date().addingTimeInterval(3)
                me.tick()
            }
        }
        var created: AXObserver?
        guard AXObserverCreate(pid, callback, &created) == .success, let observer = created else { return }
        let app = AXUIElementCreateApplication(pid)
        let refcon = Unmanaged.passUnretained(self).toOpaque()
        for name in [kAXSheetCreatedNotification, kAXWindowCreatedNotification] {
            AXObserverAddNotification(observer, app, name as CFString, refcon)
        }
        CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(observer), .defaultMode)
        axObserver = observer
    }

    /// 120ms polling only while Chrome is running (or a prompt is up) — otherwise there is nothing to watch.
    private func refreshTimer() {
        let chromeRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: Self.chromeBundleID).isEmpty
        if chromeRunning || currentPrompt != nil || allowsAnyApp() {
            if timer == nil { setTimerInterval(Self.idleInterval) }
        } else {
            timer?.invalidate()
            timer = nil
        }
    }

    /// Slow while nothing suggests a prompt is coming, fast (80ms — the length of the flash before the cover appears) while one is
    /// likely. `tick()` switches between the two, so an idle Mac isn't woken a dozen times a second for nothing.
    private static let idleInterval: TimeInterval = 0.25
    private static let hotInterval: TimeInterval = 0.08

    private func setTimerInterval(_ interval: TimeInterval) {
        guard interval != timerInterval || timer == nil else { return }
        timer?.invalidate()
        timerInterval = interval
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        // Lets macOS coalesce these wakeups with other timers instead of waking the CPU for each one.
        timer?.tolerance = interval / 2
    }

    // MARK: - Detection

    private func tick() {
        tickCount &+= 1
        let chromeApp = NSRunningApplication.runningApplications(withBundleIdentifier: Self.chromeBundleID).first
        if chromeApp?.isActive == true { lastChromeFrontAt = Date() }
        let recentChrome = lastChromeFrontAt.map { Date().timeIntervalSince($0) < Self.chromeRecency } ?? false
        // Battery: fast only while a prompt is plausible (Chrome frontmost/just was, an app just came forward, or one is up).
        let anyApp = allowsAnyApp()
        let hot = recentChrome || currentPrompt != nil || (anyApp && Date() < boostUntil)
        setTimerInterval(hot ? Self.hotInterval : (anyApp ? Self.idleInterval : 1.0))
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
        let chromeFront = chromeApp?.isActive ?? false
        // Sheets (like Safari's AutoFill one) belong to the app in front. Any-app mode checks whichever it is, except Glance itself.
        let frontPID = NSWorkspace.shared.frontmostApplication?.processIdentifier
        let sheetPID: pid_t? = anyApp
            ? frontPID.flatMap { $0 == ProcessInfo.processInfo.processIdentifier ? nil : $0 }
            : (chromeFront ? chromeApp?.processIdentifier : nil)
        // The accessibility-tree walk is the costly part: look for a *new* Chrome sheet every 3rd tick, but keep checking one we already track.
        let tracking = currentPrompt != nil
        let scanSheet = tickCount % 4 == 0 || tracking
        Task.detached(priority: .utility) { [weak self] in
            let found = Self.findPrompt(sheetPID: sheetPID, chromeFrontmost: chromeFront, chromeRecent: recentChrome, scanSheet: scanSheet, tracking: tracking, anyApp: anyApp)
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
        currentPrompt = found
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

    private nonisolated static func findPrompt(sheetPID: pid_t?, chromeFrontmost: Bool, chromeRecent: Bool, scanSheet: Bool, tracking: Bool, anyApp: Bool) -> AuthPrompt? {
        // `tracking`: a prompt already accepted stays visible to us for as long as it is on screen, however long the user takes.
        if chromeRecent || chromeFrontmost || tracking || anyApp, let prompt = findSystemPrompt(tracking: tracking, anyApp: anyApp) { return prompt }
        if scanSheet, let sheetPID { return findSheet(pid: sheetPID) }
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
            return AuthPrompt(key: "\(pid)-\(number)", pid: pid, frame: frame, axWindow: match ?? windows.first, roots: windows)
        }
        return nil
    }

    /// An auth sheet or dialog inside an app's own window (Chrome's, Safari's AutoFill sheet, ...), found by its Touch ID / password wording.
    private nonisolated static func findSheet(pid: pid_t) -> AuthPrompt? {
        for window in axWindows(of: pid) {
            let candidates = children(window, kAXChildrenAttribute) + children(window, "AXSheets") + [window]
            for element in candidates {
                let subrole = string(element, kAXSubroleAttribute)
                let isDialog = string(element, kAXRoleAttribute) == kAXSheetRole
                    || subrole == kAXDialogSubrole || subrole == kAXSystemDialogSubrole
                guard isDialog, containsAuthControls(element), let frame = windowFrame(element) else { continue }
                return AuthPrompt(key: "sheet-\(pid)", pid: pid, frame: frame, axWindow: nil, roots: [element])
            }
        }
        return nil
    }

    // MARK: - Password mode

    /// Presses "Use Password…" if needed, waits for the secure field, focuses it, and checks the system really focused it.
    /// Returns false (nothing typed) unless the next keystrokes will land in that field.
    func prepareForPassword(timeout: Duration = .seconds(7)) async -> Bool {
        let started = ContinuousClock.now
        let deadline = started + timeout
        var pressed = false
        // Re-reads `currentPrompt` each pass: pressing the button can replace the window.
        while ContinuousClock.now < deadline, let prompt = currentPrompt {
            let step = await Task.detached { Self.passwordStep(prompt, press: !pressed) }.value
            if step.pressed && !pressed { Self.log.notice("password mode: pressed the password button at \(String(describing: ContinuousClock.now - started), privacy: .public)") }
            if step.focused {
                Self.log.notice("password mode: field focused at \(String(describing: ContinuousClock.now - started), privacy: .public)")
                return true
            }
            pressed = pressed || step.pressed
            try? await Task.sleep(for: .milliseconds(20))
        }
        Self.log.notice("password mode: gave up (pressed=\(pressed), prompt still there=\(self.currentPrompt != nil))")
        return false
    }

    private nonisolated static func passwordStep(_ prompt: AuthPrompt, press: Bool) -> (focused: Bool, pressed: Bool) {
        // System prompts rebuild their window tree when switching modes, so re-read it each time.
        var roots = prompt.axWindow != nil ? axWindows(of: prompt.pid) : prompt.roots
        // After "Enter Password…" an in-app sheet can hand over to a separate system dialog, so look there for the field too.
        if prompt.axWindow == nil, find(in: roots, where: isSecureField) == nil,
           let system = findSystemPrompt(tracking: true, anyApp: true) { roots += system.roots }
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
