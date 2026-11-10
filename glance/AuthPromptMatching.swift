//
//  AuthPromptMatching.swift
//  glance
//
//  The pure "is this a prompt we may type the Mac password into" rules, kept free of AppKit/Accessibility so
//  tools/auth_match_selftest.swift can test them.
//

import Foundation

enum AuthPromptMatching {
    /// Apple apps whose own lock screen (a plain window, not a dialog) takes the Mac password.
    static let lockScreenBundleIDs: Set<String> = ["com.apple.Passwords", "com.apple.Notes", "com.apple.ScreenContinuity"]

    /// Lowercased, with Apple's typographic ellipsis/apostrophe folded to ASCII so "Use Password…" matches "use password...".
    static func normalized(_ text: String) -> String {
        text.lowercased().replacingOccurrences(of: "…", with: "...").replacingOccurrences(of: "’", with: "'")
    }

    /// Where the process's executable lives decides trust, not its bundle ID or window title, which any app can claim.
    /// Apple's own apps and daemons live under /System (Safari's cryptex path included); Chrome is the one outside app we serve.
    static func isTrustedExecutablePath(_ path: String?) -> Bool {
        guard let path else { return false }
        return path.hasPrefix("/System/") || path.hasPrefix("/usr/") || path.contains("/Google Chrome.app/Contents/")
    }

    /// "Passwords Is Locked" / "This note is locked": a static label only. Text areas and fields hold the user's own words
    /// ("the door is locked") and must never count.
    static func isLockLabel(role: String?, text: String) -> Bool {
        role == "AXStaticText" && normalized(text).contains(" is locked")
    }

    /// A lock window must also ask for a password: a secure field, or wording about Touch ID / the password.
    static func asksForPassword(text: String) -> Bool {
        let t = normalized(text)
        // Whole word: the app's own name ("Passwords Is Locked") must not count as asking for one.
        return t.range(of: "\\bpassword\\b", options: .regularExpression) != nil || t.contains("touch id")
    }

    static let authSheetWording = ["touch id", "use password", "enter password", "verify it"]
}
