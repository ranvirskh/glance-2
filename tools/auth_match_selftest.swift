//
//  auth_match_selftest.swift
//  glance (tools)
//
//  Tests the rules deciding where the Mac password may be typed. Run from the repo root:
//
//      swiftc -o /tmp/auth_match_selftest glance/AuthPromptMatching.swift tools/auth_match_selftest.swift && /tmp/auth_match_selftest
//

import Foundation

nonisolated(unsafe) var failures = 0
func check(_ ok: Bool, _ name: String) { if !ok { failures += 1; print("FAIL: \(name)") } }

@main
struct AuthMatchSelfTest {
    static func main() {
        typealias M = AuthPromptMatching
        check(M.isTrustedExecutablePath("/System/Applications/Passwords.app/Contents/MacOS/Passwords"), "Apple app trusted")
        check(M.isTrustedExecutablePath("/System/Library/CoreServices/coreautha.app/Contents/MacOS/coreautha"), "system daemon trusted")
        check(M.isTrustedExecutablePath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"), "Chrome trusted")
        check(!M.isTrustedExecutablePath("/Applications/Zoom.app/Contents/MacOS/zoom.us"), "third-party app not trusted")
        check(!M.isTrustedExecutablePath("/Users/x/Downloads/SecurityAgent.app/Contents/MacOS/SecurityAgent"), "app named like a system one not trusted")
        check(!M.isTrustedExecutablePath(nil), "no path not trusted")

        check(M.isLockLabel(role: "AXStaticText", text: "Passwords Is Locked"), "Passwords lock text")
        check(M.isLockLabel(role: "AXStaticText", text: "This note is locked."), "Notes lock text")
        check(!M.isLockLabel(role: "AXTextArea", text: "the door is locked"), "note body text is not a lock")
        check(!M.isLockLabel(role: "AXTextField", text: "account is locked"), "field text is not a lock")
        check(!M.isLockLabel(role: "AXStaticText", text: "Unlock"), "unrelated label")

        check(M.asksForPassword(text: "Enter the password for the user “Ranvir” to unlock."), "password wording")
        check(M.asksForPassword(text: "Touch ID or enter your password to continue."), "touch id wording")
        check(!M.asksForPassword(text: "Passwords Is Locked"), "title alone does not ask")
        check(M.normalized("Use Password…") == "use password...", "ellipsis folded")

        if failures == 0 { print("auth_match_selftest: all passed") } else { print("\(failures) failed"); exit(1) }
    }
}
