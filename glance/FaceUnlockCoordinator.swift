//
//  FaceUnlockCoordinator.swift
//  glance
//
//  Connects face recognition to the actual unlock path. Off by default; user opts in after validating accuracy in Face Lab.
//
//  Known limitation: LivenessAnalyzer defeats a photo but not a replayed video (real non-rigid motion looks live) — a successful spoof types the real macOS password.
//

import Foundation
import CoreGraphics
import Observation
import OSLog

@Observable
@MainActor
final class FaceUnlockCoordinator {
    private let pocController: POCController
    let lockMonitor = LockMonitor()
    let camera = CameraManager()
    let pipeline = FaceRecognitionPipeline()

    /// Persisted via GlanceSettings. Setting to false cancels any in-flight scan and disarms the overlay immediately.
    var isEnabled: Bool {
        didSet {
            GlanceSettings.shared.isFaceUnlockEnabled = isEnabled
            if !isEnabled { disarmOverlay() }
        }
    }

    /// Kept independent from Face Lab's own `threshold` so tuning the debug tool never silently changes the real unlock gate.
    var matchThreshold: Float {
        didSet { GlanceSettings.shared.matchThreshold = matchThreshold }
    }
    /// Shares its setting with NotchOverlayController's scanning timeout, so the background loop stops in step with the UI collapsing.
    private var scanWindowDuration: TimeInterval {
        TimeInterval(GlanceSettings.shared.faceDetectionSeconds)
    }
    /// A wake often catches the owner while they are still looking away from
    /// the camera. Require a sustained non-match rather than a few early
    /// frames before giving the failure animation.
    private let wrongFaceGraceDuration: Duration = .seconds(2)

    private(set) var statusMessage = "Idle"
    private(set) var lastOutcome: String?

    private var hasArmedForCurrentLock = false
    /// One-shot per lock session — an auto-retry that could itself auto-retry would loop the camera for the whole lock session.
    private var hasAutoRetriedForCurrentLock = false
    private var scanTask: Task<Void, Never>?
    /// Bumped by every `startScanCycle()`; a cycle bails once superseded (see `runScanCycle(generation:)`).
    private var scanGeneration = 0
    /// When the last scan cycle was armed — collapses a single wake into a single arm (see `.wake` branch of `evaluateTrigger`).
    private var lastArmedAt: ContinuousClock.Instant?
    /// One lid-open fires several wake signals within a few hundred ms of each other; anything in this window counts as the same wake.
    private let rearmDebounce: Duration = .seconds(2)
    /// Held separately from `scanTask` since it's scheduled from inside the scan task it follows — reusing `scanTask` would self-cancel it.
    private var autoRetryTask: Task<Void, Never>?
    /// Gap between headless auto-retries, just to keep the camera from restarting in a tight loop.
    private let headlessRetryDelay: Duration = .seconds(1)

    /// When off, no notch/pill presence at all — every overlay call in this file is conditioned on this rather than just skipping the video.
    private var showsUI: Bool { GlanceSettings.shared.showUnlockAnimation }

    /// Reads the space key on the lock screen for the "On space" trigger; only runs while locked + opted in.
    private let spaceKeyMonitor = SpaceKeyMonitor()

    /// What a scan is gating: the lock screen, or a Touch ID prompt raised while the Mac is unlocked (Chrome autofill etc.).
    private enum ScanContext { case lockScreen, inSessionAuth }
    private var scanContext: ScanContext = .lockScreen
    /// Latched once an in-session scan matches, so the prompt changing under the password sequence doesn't cancel it.
    private var inSessionMatched = false
    private var lastInSessionTypedAt: ContinuousClock.Instant?
    private static let retryCooldown: Duration = .seconds(20)
    private let interceptor = SystemAuthInterceptor()
    private static let lockLog = Logger(subsystem: "glance.auth", category: "unlock")
    /// Vision's capture-quality score a frame needs before it may teach the profile. Laptop webcams at lock-screen distance
    /// score 0.29–0.33, so a higher bar meant learning never ran; the match-strength requirement is what keeps it safe.
    private static let learningMinimumQuality: Float = 0.25

    init(pocController: POCController) {
        self.pocController = pocController
        self.isEnabled = GlanceSettings.shared.isFaceUnlockEnabled
        self.matchThreshold = GlanceSettings.shared.matchThreshold
        spaceKeyMonitor.onSpaceKeyDown = { [weak self] in self?.handleSpaceKeyPress() }
        observeLockAndWakeEvents()

        interceptor.isAllowed = { [weak self] in
            guard let self else { return false }
            return self.isEnabled && (GlanceSettings.shared.interceptSystemAuth || GlanceSettings.shared.interceptAnyPasswordPrompt)
        }
        interceptor.allowsAnyApp = { GlanceSettings.shared.interceptAnyPasswordPrompt }
        interceptor.onPromptAppeared = { [weak self] _ in self?.handleSystemPrompt() }
        interceptor.onPromptGone = { [weak self] in self?.handleSystemPromptGone() }
        interceptor.start()
    }

    // MARK: - In-session auth prompts (Chrome / CoreAuthUI / SecurityAgent)

    private func handleSystemPrompt() {
        // After typing the password once, a dialog that comes straight back means it was wrong (e.g. the Mac password changed).
        // Typing it again would only run up failed attempts, so leave the prompt to the user for a while.
        if let typedAt = lastInSessionTypedAt, ContinuousClock.now - typedAt < Self.retryCooldown { return }
        // Any unmet gate leaves the prompt untouched, so Touch ID / typing the password works as normal.
        guard isEnabled, GlanceSettings.shared.interceptSystemAuth || GlanceSettings.shared.interceptAnyPasswordPrompt,
              !LockMonitor.isScreenActuallyLocked(),
              !NotchOverlayController.shared.isArmed,
              NotchOverlayController.shared.phase != .scanning,
              SecureCredentialManager.isSessionUnlocked,
              SecureCredentialManager.hasStoredPassword()
        else {
            Logger(subsystem: "glance.auth", category: "coordinator").notice("""
                prompt left alone: enabled=\(self.isEnabled) toggle=\(GlanceSettings.shared.interceptSystemAuth) \
                sessionUnlocked=\(SecureCredentialManager.isSessionUnlocked) hasPassword=\(SecureCredentialManager.hasStoredPassword())
                """)
            return
        }

        Self.lockLog.notice("prompt accepted: covering it and scanning")
        IslandBridge.show(symbol: "faceid", title: "Face ID", subtitle: "Looking for you…")
        if usesNotch(for: .inSessionAuth) {
            NotchOverlayController.shared.present(onRetry: { [weak self] in self?.startScanCycle(.inSessionAuth) })
        }
        startScanCycle(.inSessionAuth)
    }

    /// The user answered the prompt themselves (Touch ID, typed, cancelled) — stop scanning and clean up.
    private func handleSystemPromptGone() {
        guard scanContext == .inSessionAuth, !inSessionMatched else { return }
        scanTask?.cancel()
        scanTask = nil
        scanGeneration &+= 1
        camera.stop()
        if usesNotch(for: .inSessionAuth) { NotchOverlayController.shared.dismissImmediately() }
    }

    /// Whether Glance draws its own notch scan for this kind of scan. In-app prompts are shown by Isle instead when it is running.
    /// The lock-screen scan always uses Glance's own overlay: Isle's presence on the lock screen isn't something to rely on.
    private func usesNotch(for context: ScanContext) -> Bool {
        showsUI && !(context == .inSessionAuth && IslandBridge.isleShowsScan)
    }

    private func isContextLive(_ context: ScanContext) -> Bool {
        switch context {
        case .lockScreen: LockMonitor.isScreenActuallyLocked()
        case .inSessionAuth: interceptor.currentPrompt != nil
        }
    }

    /// Re-subscribes on every change — `withObservationTracking` only fires once per registration.
    private func observeLockAndWakeEvents() {
        withObservationTracking {
            _ = lockMonitor.isScreenLocked
            _ = lockMonitor.wakeEventCount
            _ = lockMonitor.isSleeping
            // Also tracked so screensaver-stop and display-only wakes still wake this up.
            _ = lockMonitor.eventCount
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                self?.observeLockAndWakeEvents()
                // CGSession's reported state can lag the true state right after wake, so allow up to ~320ms for it to settle — but
                // polling means a lock that is already visible proceeds at once instead of always paying the full wait.
                for _ in 0..<8 where !LockMonitor.isScreenActuallyLocked() {
                    try? await Task.sleep(nanoseconds: 40_000_000)
                }
                self?.evaluateTrigger()
            }
        }
    }

    private func evaluateTrigger() {
        guard LockMonitor.isScreenActuallyLocked() else {
            hasArmedForCurrentLock = false
            hasAutoRetriedForCurrentLock = false
            disarmOverlay()
            return
        }
        guard !lockMonitor.isSleeping else { return }

        // `.wake` (sleep, display sleep, or screensaver stopping) is an explicit "let me back in," so clear the one-shot guard.
        // `isWithinRecentArmBurst` keeps the several wake signals from one lid-open from each re-arming and fighting over the camera.
        if lockMonitor.lastEvent == .wake, !isWithinRecentArmBurst {
            hasArmedForCurrentLock = false
        }

        // Runs before the hasArmedForCurrentLock guard — the space monitor's lifetime is tied to "locked + opted in," not to whether a scan already ran.
        updateSpaceMonitor()

        guard isEnabled, !hasArmedForCurrentLock else { return }
        guard let signal = requiredTrigger(for: lockMonitor.lastEvent) else { return }
        // A pinned display that isn't connected bails entirely rather than showing up elsewhere; "Main display" (nil) always resolves.
        guard NotchGeometry.preferredScreen() != nil else { return }

        guard SecureCredentialManager.isSessionUnlocked else {
            statusMessage = "Face unlock is on, but the session is locked — authenticate once from Password settings first."
            Self.lockLog.notice("lock screen: not scanning, Glance's session is locked")
            return
        }
        guard SecureCredentialManager.hasStoredPassword() else {
            statusMessage = "Face unlock is on, but no password is stored yet."
            Self.lockLog.notice("lock screen: not scanning, no stored password")
            return
        }

        // A deselected trigger means "don't auto-scan for this signal," not "do nothing" — the user can still opt in by hand.
        let shouldAutoScan = GlanceSettings.shared.unlockTriggers.contains(signal)

        // Headless has nothing to arm/hover, so if this signal isn't selected there's nothing to do — and hasArmedForCurrentLock
        // must stay false, or a later selected signal could never fire (nothing else calls arm() to reset it).
        guard showsUI || shouldAutoScan else { return }

        hasArmedForCurrentLock = true
        lastArmedAt = .now
        // The camera's warm-up is the slowest part of a scan, so it runs alongside the notch delay below rather than after it.
        if shouldAutoScan { Task { [weak self] in await self?.camera.start() } }
        Task { [weak self] in
            // arm() only shows a small closed notch silhouette, so this only needs a brief buffer past the login window's entrance.
            try? await Task.sleep(nanoseconds: 150_000_000)
            await self?.arm(autoScan: shouldAutoScan)
        }
    }

    /// Whether the last arm was recent enough to be part of the same wake burst rather than a new one.
    private var isWithinRecentArmBurst: Bool {
        guard let lastArmedAt else { return false }
        return ContinuousClock.now - lastArmedAt < rearmDebounce
    }

    /// nil for signals that shouldn't arm anything — including a nil `lastEvent`, or the first observation would fire regardless of user selection.
    private func requiredTrigger(for event: LockEventKind?) -> UnlockTrigger? {
        switch event {
        case .wake: return .onWake
        case .screenLocked: return .onLock
        case .screenUnlocked, .willSleep, nil: return nil
        }
    }

    private func disarmOverlay() {
        scanTask?.cancel()
        scanTask = nil
        // Bumping makes any cycle still suspended at `await camera.start()` inert, rather than resuming and re-showing the overlay.
        scanGeneration &+= 1
        autoRetryTask?.cancel()
        autoRetryTask = nil
        camera.stop()
        NotchOverlayController.shared.disarm()
        // Covers isEnabled being switched off directly, keeping "disarmed" and "not listening for space" in lockstep.
        spaceKeyMonitor.stop()
    }

    /// Idempotent and safe to call on every lock/wake event. Deliberately does not prompt for Input Monitoring — a missing grant just means "don't listen."
    private func updateSpaceMonitor() {
        let shouldListen = isEnabled
            && GlanceSettings.shared.unlockTriggers.contains(.onSpace)
            && LockMonitor.isScreenActuallyLocked()
            && SpaceKeyMonitor.hasInputMonitoringAccess()
        if shouldListen {
            spaceKeyMonitor.start()
        } else {
            spaceKeyMonitor.stop()
        }
    }

    /// Runs the same gate chain as `evaluateTrigger`, then starts a scan. Independent of `LockMonitor` events, so doesn't touch `hasArmedForCurrentLock`.
    private func handleSpaceKeyPress() {
        guard isEnabled,
              GlanceSettings.shared.unlockTriggers.contains(.onSpace),
              LockMonitor.isScreenActuallyLocked(),
              NotchGeometry.preferredScreen() != nil,
              SecureCredentialManager.isSessionUnlocked,
              SecureCredentialManager.hasStoredPassword()
        else { return }

        // Already looking — swallows auto-repeat/double-presses and lets "On wake"/"On lock" override "On space" with no special-casing.
        guard NotchOverlayController.shared.phase != .scanning else { return }

        guard showsUI else {
            // Headless: no overlay, just scan.
            startScanCycle()
            return
        }
        if NotchOverlayController.shared.isArmed {
            // Closed pill/notch already up — expand and scan, like a hover retry.
            startScanCycle()
        } else {
            Task { [weak self] in await self?.arm(autoScan: true) }
        }
    }

    /// Either way the overlay still arms — a deselected trigger only skips the automatic scan, leaving hover-to-start available.
    private func arm(autoScan: Bool) async {
        guard LockMonitor.isScreenActuallyLocked() else {
            camera.stop() // undo the early warm-up started in evaluateTrigger
            return
        }
        guard showsUI else {
            // Headless: evaluateTrigger() already guaranteed autoScan is true here, so this is just "start scanning."
            startScanCycle()
            return
        }
        NotchOverlayController.shared.arm { [weak self] in
            self?.startScanCycle()
        }
        if autoScan {
            startScanCycle()
        }
    }

    /// Called on arm, and again whenever the overlay hover-activates.
    private func startScanCycle(_ context: ScanContext = .lockScreen) {
        scanTask?.cancel()
        scanGeneration &+= 1
        let generation = scanGeneration
        scanContext = context
        inSessionMatched = false
        scanTask = Task { [weak self] in
            await self?.runScanCycle(generation: generation, context: context)
        }
    }

    /// `generation` is what makes overlapping cycles safe: `Task.cancel()` is cooperative, so a superseded cycle still runs to the
    /// end of this function, and its global side effects (`camera.stop()` etc.) could otherwise land on the newer cycle instead
    /// of itself. This was a real bug — a superseded `camera.stop()` queued behind the newer cycle's `startRunning()` made the
    /// camera visibly switch on then die mid-warm-up, leaving the surviving cycle polling a dead session and never unlocking.
    private func runScanCycle(generation: Int, context: ScanContext) async {
        guard isContextLive(context) else { return }

        await camera.start()
        guard generation == scanGeneration else { return }

        if let error = camera.errorMessage {
            Self.lockLog.error("camera unavailable: \(error, privacy: .public)")
            statusMessage = error
            camera.stop()
            return
        }

        let showsUI = usesNotch(for: context)
        if showsUI {
            NotchOverlayController.shared.beginScanning()
        }
        statusMessage = "Looking for your face…"

        let outcome = await observeScanWindow(
            deadline: Date().addingTimeInterval(scanWindowDuration),
            requireOverlayScanning: showsUI,
            context: context
        )

        // A newer cycle now owns the camera and overlay — leave both alone, and leave the auto-retry one-shot unspent.
        guard generation == scanGeneration else { return }

        camera.stop()
        if context == .inSessionAuth { reportToIsle(outcome) }
        let sinceArm = lastArmedAt.map { String(describing: ContinuousClock.now - $0) } ?? "n/a"
        Self.lockLog.notice("scan finished: \(String(describing: outcome), privacy: .public) (\(String(describing: context), privacy: .public)) \(sinceArm, privacy: .public) after arming")

        switch outcome {
        case .matched:
            // The unlock already happened inside observeScanWindow — this only decides whether anything is shown about it.
            if showsUI {
                NotchOverlayController.shared.finish(success: true)
            }
        case .passwordFieldUnavailable:
            statusMessage = "Face matched, but the password field wasn't reachable — use Touch ID or type it."
            if showsUI { NotchOverlayController.shared.finish(success: false) }
        case .consistentlyWrongFace:
            statusMessage = "Face not recognized."
            if showsUI {
                NotchOverlayController.shared.finish(success: false)
                statusMessage = "Face not recognized — hover the notch to try again."
                scheduleAutoRetryIfEnabled(after: NotchOverlayController.shared.failureHoldDuration)
            } else {
                scheduleAutoRetryIfEnabled(after: headlessRetryDelay)
            }
        case .spoofSuspected:
            statusMessage = "Couldn't confirm a live face."
            if showsUI {
                NotchOverlayController.shared.finish(success: false)
                statusMessage = "Couldn't confirm a live face — hover the notch to try again."
                scheduleAutoRetryIfEnabled(after: NotchOverlayController.shared.failureHoldDuration)
            } else {
                scheduleAutoRetryIfEnabled(after: headlessRetryDelay)
            }
        case .noResolution:
            statusMessage = "No face detected."
            if showsUI {
                // No explicit collapse call: NotchOverlayController's own scanning timeout fires on the same mark and collapses itself.
                statusMessage = "No face detected — hover the notch to try again."
                scheduleAutoRetryIfEnabled(after: NotchOverlayController.shared.collapseAnimationDuration)
            } else {
                scheduleAutoRetryIfEnabled(after: headlessRetryDelay)
            }
        }
    }

    /// The scan's result as Isle's "Face ID" pop-up (does nothing unless Isle is running and showing the scan).
    private func reportToIsle(_ outcome: ScanOutcome) {
        switch outcome {
        case .matched:
            IslandBridge.show(symbol: "checkmark.circle.fill", title: "Unlocked", subtitle: "Password filled in")
            IslandBridge.playSuccessHaptic()
        case .consistentlyWrongFace: IslandBridge.show(symbol: "xmark.circle.fill", title: "Face not recognized")
        case .spoofSuspected: IslandBridge.show(symbol: "exclamationmark.shield.fill", title: "Couldn't confirm a live face")
        case .noResolution: IslandBridge.show(symbol: "faceid", title: "No face detected")
        case .passwordFieldUnavailable:
            IslandBridge.show(symbol: "exclamationmark.triangle.fill", title: "Matched, but couldn't fill it in", subtitle: "Use Touch ID or type it")
        }
    }

    /// Feeds a successful unlock back into the profile. Deliberately strict, since a wrong sample here would loosen future matches:
    /// liveness must have been on and confirmed (so a photo can't teach the profile), the match must clear the threshold by a margin
    /// (not just scrape past it), and the frame must be decent quality. The store adds its own limits (rate, duplicates, cap).
    private func learnFromMatch(_ match: ScoredIdentity, result: FaceRecognitionResult, livenessEnabled: Bool) {
        // Measured against the guided-enrollment samples only. Against the full template (which includes earlier learned samples),
        // each learned sample would move the bar toward itself and a look-alike could slowly pull the profile their way.
        let enrolled = match.identity.samples.filter { $0.pose != FaceEnrollmentStore.learnedPose }.map(\.embedding)
        let similarity = FaceEmbedding.average(enrolled).map { FaceEmbedding.cosineSimilarity(result.embedding, $0) } ?? 0
        let quality = result.quality ?? 0
        guard GlanceSettings.shared.adaptiveLearningEnabled, livenessEnabled,
              similarity >= matchThreshold + 0.06, quality >= Self.learningMinimumQuality else {
            Self.lockLog.notice("learning skipped: enabled=\(GlanceSettings.shared.adaptiveLearningEnabled) liveness=\(livenessEnabled) similarity=\(similarity, format: .fixed(precision: 3)) needs>=\(self.matchThreshold + 0.06, format: .fixed(precision: 3)) quality=\(quality, format: .fixed(precision: 2)) needs>=\(Self.learningMinimumQuality, format: .fixed(precision: 2))")
            return
        }
        do {
            let stored = try FaceEnrollmentStore.shared.learnSample(
                for: match.identity.id, embedding: result.embedding, quality: result.quality, embedder: pipeline.embedder
            )
            Self.lockLog.notice("learning: \(stored ? "stored a new sample" : "nothing new (too soon or near-duplicate)", privacy: .public)")
        } catch {
            Logger(subsystem: "glance.auth", category: "learning").error("learning failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// `delay` waits out whatever the overlay is still showing so the retry doesn't start underneath the previous outcome.
    private func scheduleAutoRetryIfEnabled(after delay: Duration) {
        // The one-shot is per lock session; an in-session prompt must not spend it.
        guard scanContext == .lockScreen, GlanceSettings.shared.autoRetryOnce, !hasAutoRetriedForCurrentLock else { return }
        hasAutoRetriedForCurrentLock = true
        autoRetryTask?.cancel()
        autoRetryTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled, let self else { return }
            // Re-check rather than trust the delay: the user may have unlocked by password or retried manually while this waited.
            guard LockMonitor.isScreenActuallyLocked(), self.isEnabled else { return }
            if self.showsUI {
                guard NotchOverlayController.shared.phase == .closed else { return }
            }
            self.startScanCycle()
        }
    }

    private enum ScanOutcome {
        case matched
        case consistentlyWrongFace
        /// A deny cue (glare, device rectangle) fired — actively rejected as a spoof regardless of match. Same failure path as `.consistentlyWrongFace`.
        case spoofSuspected
        case noResolution
        /// In-session only: the face matched but the prompt never offered a focused password field, so nothing was typed.
        case passwordFieldUnavailable
    }

    /// Recognition and liveness run concurrently and each latches when it succeeds, so unlock fires the moment the second lands;
    /// liveness never fails the scan by staying undecided, it just keeps scanning until `deadline`.
    /// `requireOverlayScanning` bails early once the overlay's own timeout collapses the UI — only applied when there is an
    /// overlay, since headlessly `phase` never becomes `.scanning` at all.
    private func observeScanWindow(deadline: Date, requireOverlayScanning: Bool, context: ScanContext) async -> ScanOutcome {
        let livenessEnabled = GlanceSettings.shared.livenessChecksEnabled
        let liveness = LivenessAnalyzer()
        liveness.modeProvider = { GlanceSettings.shared.livenessMode }
        /// Set by the first consecutive non-match. A gap in face detection or
        /// a valid match clears it, so only a sustained wrong face resolves the scan.
        var wrongFaceStartedAt: ContinuousClock.Instant?

        /// Cleared the moment a detected face fails to match, so a latched match can't be handed to whoever steps in next.
        var readyMatch: ScoredIdentity?
        /// Turning liveness off in Settings makes this half permanently ready.
        var livenessConfirmed = !livenessEnabled
        /// Last frame's selected face, passed back so `selectDominantFace` stays on the same person instead of flip-flopping.
        var lastFaceBoundingBox: CGRect?
        // Where the time goes, for the log: camera warm-up vs. finding a face vs. confirming it.
        let scanStart = ContinuousClock.now
        var firstFrameAt: Duration?
        var firstFaceAt: Duration?
        /// Cheap way to detect "no new camera frame yet" vs. "fresh frame" — without it a repeat frame would corrupt the liveness motion signal.
        var lastProcessedFrameID: UInt64?

        while Date() < deadline, !Task.isCancelled,
              !requireOverlayScanning || NotchOverlayController.shared.phase == .scanning {
            guard isContextLive(context) else { return .noResolution }

            guard let frame = camera.currentFrame, frame.id != lastProcessedFrameID else {
                // 20ms keeps the liveness window's sample count high while staying close to the camera's native ~33ms cadence.
                try? await Task.sleep(nanoseconds: 20_000_000)
                continue
            }
            lastProcessedFrameID = frame.id
            if firstFrameAt == nil { firstFrameAt = ContinuousClock.now - scanStart }

            let pipeline = self.pipeline
            let previousBoundingBox = lastFaceBoundingBox
            let outcome = await Task.detached(priority: .userInitiated) { () -> (FaceRecognitionResult, LivenessFrame)? in
                guard let result = try? pipeline.recognize(in: frame.image, preferNear: previousBoundingBox) else { return nil }
                let faceCrop = CameraManager.renderCrop(from: frame, imageRect: result.face.boundingBox)
                return (result, LivenessFeatureExtractor.extract(from: result, frame: frame.image, faceCrop: faceCrop))
            }.value

            guard let (result, livenessFrame) = outcome else {
                wrongFaceStartedAt = nil
                lastFaceBoundingBox = nil
                try? await Task.sleep(nanoseconds: 20_000_000)
                continue
            }
            lastFaceBoundingBox = result.face.normalizedBoundingBox
            if firstFaceAt == nil { firstFaceAt = ContinuousClock.now - scanStart }

            // Fed regardless of match, so liveness stays a genuinely independent gate rather than one starved by recognition confidence.
            var confirmingCue: LivenessCue?
            if livenessEnabled {
                let snapshot = liveness.observe(livenessFrame)
                switch snapshot.decision {
                case .denied:
                    // Overrides everything, including a match and any confirmation that already happened.
                    lastOutcome = snapshot.decision.denialReason
                    return .spoofSuspected
                case .confirmed(let cue):
                    livenessConfirmed = true
                    confirmingCue = cue
                case .pending:
                    break
                }
            }

            // `activeIdentities`, not `identities`: someone switched off on the Your Face page stays enrolled but must not unlock.
            let scored = pipeline.score(result.embedding, against: FaceEnrollmentStore.shared.activeIdentities)
            let matched = pipeline.bestMatch(in: scored, threshold: matchThreshold)

            if let matched {
                wrongFaceStartedAt = nil
                readyMatch = matched
            } else {
                readyMatch = nil
                if wrongFaceStartedAt == nil {
                    wrongFaceStartedAt = .now
                }
                if ContinuousClock.now - wrongFaceStartedAt! >= wrongFaceGraceDuration {
                    return .consistentlyWrongFace
                }
            }

            if let readyMatch, livenessConfirmed {
                statusMessage = "Recognized — unlocking…"
                Self.lockLog.notice("timing: first frame \(String(describing: firstFrameAt), privacy: .public), first face \(String(describing: firstFaceAt), privacy: .public), matched+live \(String(describing: ContinuousClock.now - scanStart), privacy: .public) after scan start")
                let livenessNote = livenessEnabled
                    ? (confirmingCue.map { "live via \($0.title)" } ?? "liveness clear")
                    : "liveness off"
                lastOutcome = "Matched \(readyMatch.identity.name) at \(String(format: "%.3f", readyMatch.centroidSimilarity)), \(livenessNote)."
                if context == .inSessionAuth {
                    inSessionMatched = true
                    // Types nothing unless the system confirms the password field has focus.
                    guard await interceptor.prepareForPassword() else { return .passwordFieldUnavailable }
                    lastInSessionTypedAt = .now
                }
                // In-session: re-check focus on the typing thread, so a dialog cancelled since the check above gets no keystrokes.
                var focusCheck: (@Sendable () -> Bool)?
                if context == .inSessionAuth { focusCheck = { SystemAuthInterceptor.isSecureFieldFocused() } }
                let typed = await pocController.injectStoredPassword(requireAuthoritativeLock: context == .lockScreen, beforeTyping: focusCheck)
                Self.lockLog.notice("injection result (typed=\(typed)): \(self.pocController.statusMessage, privacy: .public)")
                // In-session, a refused or failed typing must not look like a success: show the failure and give the dialog back.
                if context == .inSessionAuth, !typed { return .passwordFieldUnavailable }
                // After the unlock, so learning can never delay or block it.
                learnFromMatch(readyMatch, result: result, livenessEnabled: livenessEnabled)
                return .matched
            }

            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return .noResolution
    }
}
