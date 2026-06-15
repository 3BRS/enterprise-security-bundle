# Session Management & Login Notifications

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Active-session listing with manual revocation, plus optional email notifications when a user signs in from a previously unseen device. Configurable per scope (`customer` / `admin`). It lets a user see *where they're signed in* and shut down a session they don't recognise — and warns them when a new device logs in.

**What it does:**
- **Records each sign-in** as a session row with the device (browser + OS), IP, approximate location (with GeoIP), and created / last-activity timestamps.
- **Shows the user their active sessions** and marks the one they're currently on; they can **revoke a single session** or **revoke all others** in one click. The current session is left non-revocable (they sign out normally instead).
- **Enforces revocation** — a revoked session signs that user out on their very next request, so "sign out my other devices" takes effect immediately without waiting for the session to expire.
- **Login notifications** — emails the user when a sign-in comes from a device/IP they haven't used before, so an unexpected login is visible to them.

## Session management

**Bundle primitives:**
- `AbstractSessionTracker` — extend it. Public API: `track($user, $sessionId, $userAgent, $ipAddress)` records a session at login (running the GeoIP lookup for country/city, and tolerating a concurrent insert with the same session id); `touch($sessionId)` updates last-activity, **throttled to once per 60 s** per session to avoid write-amplification; `revoke($record)`; `revokeOthers($currentSessionId, $user)`. Abstract hooks bind the repository lookups and Doctrine persistence (`findOneBySessionId`, `findActiveForUser`, `createNewRecord`, `save`, `commit`, …).
- `SessionRecordInterface` — the persisted session row you implement (user, sessionId, userAgent, ipAddress, country, city, createdAt, lastActivityAt, revokedAt). See [Entities & persistence](../entities-and-persistence.md).
- `UserAgentParser` (`UserAgentParserInterface`) + `UserAgentInfo` — parse the User-Agent into a human-readable browser + OS (via `matomo/device-detector`) for the list UI and the notification email.
- GeoIP (see below).
- Controllers: `AbstractSessionsListController`, `AbstractSessionRevokeController`, `AbstractSessionRevokeOthersController` — bind surface and registration in [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface). The list marks the row matching the request's session id as "current"; that current session is intentionally non-revocable (sign out instead).

**Listeners you provide** (the bundle ships no `kernel.request` listeners for this):
- **Activity tracking** — on each authenticated request call `tracker->touch($sessionId)` (the 60 s throttle is internal).
- **Revocation enforcement** — on each authenticated request, look up the current session record; if `revokedAt` is set, invalidate the PHP session, clear the security token and redirect to login (or return `401 {"error":"session_revoked"}` for JSON requests). A revoked session then signs the user out on their next request.

## Login notifications

On a successful sign-in, compute a device fingerprint with `SessionFingerprintGenerator::generate($userAgent, $ipAddress)` — `sha256(userAgent + '|' + ipAddress)`. If that fingerprint isn't already stored for the user, persist it and send a notification email (time, parsed browser/OS, IP, and country/city when a GeoIP provider is wired). Subsequent logins from the same UA + IP are a known device and send no email.

The bundle ships the fingerprint generator; the known-device store and the mailer are yours (the bundle has no mail-transport coupling).

> **First-time enable.** The known-device store is empty when you first turn `login_notifications` on, so every active user gets a notification at their next sign-in (every device is "new" until stored). To suppress the initial wave, pre-populate trusted `(user, fingerprint)` pairs before enabling.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store):

| Path | Scope | Type |
|---|---|---|
| `session_management.enabled` | customer, admin | bool |
| `login_notifications.enabled` | customer, admin | bool |
| `session_management.geoip_service` | global | string service id, or `null` (used by integrations that select GeoIP at runtime) |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            session_management.enabled: false
            login_notifications.enabled: false
        admin:
            session_management.enabled: false
            login_notifications.enabled: false
        global:
            session_management.geoip_service: ~
```

## Enabling GeoIP location lookups

The bundle binds `GeoIpLookupInterface` to `NullGeoIpLookup` by default — every lookup returns `null`, so the feature works with no GeoIP dependency. To populate country/city, override that alias with a real provider:

1. Pull in the MaxMind library (kept under composer `suggest` so non-GeoIP users don't pay for it) and download the free `GeoLite2-City.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (refreshed ~twice a week — plan a re-download job):
   ```bash
   composer require geoip2/geoip2
   ```
2. Wire `MaxMindGeoIpLookup` and point the interface alias at it:
   ```yaml
   # config/services.yaml
   services:
       ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\MaxMindGeoIpLookup:
           arguments:
               $databasePath: '%kernel.project_dir%/var/geoip/GeoLite2-City.mmdb'

       ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\GeoIpLookupInterface:
           alias: ThreeBRS\EnterpriseSecurityBundle\Session\GeoIp\MaxMindGeoIpLookup
   ```

For a different provider (IP2Location, an online API, an internal service), implement `GeoIpLookupInterface`, register it, and alias the interface to it.

> **Localhost / private IPs:** MaxMind GeoLite2 only covers public IPs. `127.0.0.1`, `::1`, RFC1918 ranges and Docker bridge networks return `null`, so locally the session UI shows an IP without country/city — expected.
>
> **Trusted proxies:** the fingerprint and stored IP use `Request::getClientIp()`. Without `framework.trusted_proxies` configured, all sessions appear to come from the proxy IP and the new-device check effectively de-duplicates by User-Agent only. See the [Symfony docs on trusted proxies](https://symfony.com/doc/current/deployment/proxies.html).
