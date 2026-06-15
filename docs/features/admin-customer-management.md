# Admin Customer Management

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

The day-to-day support actions an operator needs on a user's profile — force a password reset, block/unblock, sign out devices, review sessions. The bundle ships **no admin UI** for this (detail-page routes and admin layouts vary too much to abstract); you build a small "Security" panel on your user-detail page, wiring each action to the relevant bundle primitive. See [Controllers your app must provide §2](../controllers-you-provide.md#2-admin-actions-targeting-another-user).

## Actions and the primitives behind them

Each is a small CSRF-protected POST handler:

- **Force password reset** — set `forcePasswordChange = true` on the user (`PasswordExpiration*UserInterface`). Your force-password-change listener then redirects them to the change-password page on their next request. See [Password expiration](password-expiration.md) and [Controllers your app must provide §3](../controllers-you-provide.md#3-force-password-change-ui).
- **Block account** — set the user's `enabled` flag to `false` (your framework's user checker then rejects sign-in) **and** revoke their sessions in one step (`AbstractSessionTracker::revokeOthers()` / `revoke()`). This is **manual and indefinite** — distinct from the automatic, time-bounded [account lockout](account-lockout-rate-limiting.md) triggered by failed logins. Block = "this user is misbehaving, lock them out"; lockout = "too many wrong passwords, cool off".
- **Unblock account** — set `enabled = true`; the user can sign in again immediately.
- **Sign out from all devices** — `AbstractSessionTracker::revokeOthers()` (or revoke all). Useful after a stolen-device report or a password reset.
- **Sign out a single session** — `AbstractSessionTracker::revoke($record)`; the row stays in history, marked ended.

## Read-only tables

Backed by your `SessionRecordInterface` repository (see [Session management](session-management-login-notifications.md)):

- **Active sessions** — every non-revoked session with IP, location (if GeoIP is configured), device (parsed via `UserAgentParser`), and signed-in / last-activity timestamps.
- **Login history** — recent sessions (active and revoked), newest first. Only contains data captured **after** session management was enabled — earlier sign-ins are not retroactively visible.

## Prerequisites

- **Force password reset** depends on your force-password-change listener being registered (see §3 above).
- **Session tables** depend on `session_management.enabled` for the user's scope — if sessions aren't tracked, the panel still renders but the tables stay empty.
- There is no settings toggle for this tooling itself — it is whatever you choose to expose to your administrators.
