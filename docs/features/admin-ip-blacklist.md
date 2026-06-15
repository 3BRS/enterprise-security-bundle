# Admin IP Blacklist

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Inverse of the [whitelist](admin-ip-whitelist.md): instead of "only these IPs may reach the panel", say "these specific IPs may not". A single **global** deny-list applies to every admin-area request. Useful when you don't want to pin everyone to a fixed network but need to block a specific bad actor — a former colleague's home IP, an abuse-report exit node, a host hammering the login form.

**Bundle primitives** — the same as the whitelist (`CidrMatcher`, the `CidrList` constraint, `AbstractIpRestrictionChecker`, `AbstractIpRestrictionListener`). Bind the checker with `getSettingsKey()` returning `ip_blacklist` and `getScope()` returning `SettingsScope::ADMIN`. The listener subclass's `isRequestAllowed($ip)` returns the **inverse** of the checker's match (a match means deny). Denial is HTTP 403 with a plain-text body, identity-agnostic — any request whose client IP matches is rejected whether or not anyone is signed in, so a known-bad IP can't even reach the login form.

**Blacklist should win over the whitelist.** Register the blacklist `kernel.request` listener at a **higher priority** than the whitelist listener (e.g. 5 vs 4) so a blacklist hit short-circuits the whitelist check. That way you can keep a permissive (or absent) whitelist for the team while still blocking individual abusive IPs.

## Settings

Read at `SettingsScope::ADMIN`:

| Path | Type |
|---|---|
| `ip_blacklist.enabled` | bool |
| `ip_blacklist.global_cidrs` | list of CIDR strings |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        admin:
            ip_blacklist.enabled: false
            ip_blacklist.global_cidrs: []
```

The deny-list lives in your settings store so operators change it at runtime without redeploying. `CidrMatcher` accepts IPv4 and IPv6.

> **Fail-open by default.** Unlike the whitelist, enabling the blacklist with an empty global list locks no one out — an empty deny-list blocks nothing. Safe to toggle on as a precaution and populate later.

> **Operator note.** If you blacklist your own IP and lock yourself out, recover by clearing `ip_blacklist.enabled` / `ip_blacklist.global_cidrs` in your settings store. Behind a reverse proxy or load balancer, configure `framework.trusted_proxies` so `Request::getClientIp()` returns the real client IP — otherwise the listener compares the proxy's address against your CIDR list and you either block no one or block everyone.
