# Admin IP Whitelist

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Restrict admin-area access to a configured set of IP addresses / CIDR ranges. Two layers solve different problems: a **global** team-wide allow-list (bundle-enforced), and an optional **per-admin** personal allow-list (you build on top).

**Bundle primitives:**
- `CidrMatcher` (`CidrMatcherInterface`) — `matchesAny($ip, $cidrs)`, IPv4 (`10.0.0.0/8`, `192.168.1.1`) and IPv6 (`2001:db8::/32`, `::1`).
- `CidrList` Symfony constraint + `CidrListValidator`, and `CidrListDataTransformer` for binding a textarea/collection of CIDRs to a form field — validate operator-entered lists.
- `AbstractIpRestrictionChecker` — the global-list engine: `isFeatureEnabled()`, `getGlobalCidrs()`, `matchesGlobal($ip)`. Bind it by implementing `getSettingsKey()` (return `ip_whitelist`) and `getScope()` (return `SettingsScope::ADMIN`); it then reads `ip_whitelist.enabled` + `ip_whitelist.global_cidrs` and matches via `CidrMatcher`.
- `AbstractIpRestrictionListener` — a `kernel.request` listener that denies with **HTTP 403** (plain-text body, no redirect or login-form fallback). Implement `isFeatureEnabled()` and `isRequestAllowed($ip)`; the whitelist subclass returns the checker's "matches" result.

Access is granted when the request IP matches the global list (or, if you build the per-admin layer, the authenticated admin's own enabled list).

## The per-admin layer and admin UI (you build)

The bundle enforces the **global** list. The per-admin personal allow-lists, the admin management screens, and the "global list is mandatory when enabled" form guard are app-provided — see [Controllers your app must provide §4](../controllers-you-provide.md#4-ip-whitelist--blacklist-admin-ui). Typical design:

- A per-admin entity (enabled flag + CIDR list, validated by `CidrList`) that grants access only when **that specific admin** signs in (CIDRs stay private to that admin).
- On the anonymous login page (identity not yet known), let a request through if its IP matches **any** enabled per-admin entry, so an admin can reach the form; after authentication, enforce that the IP matches **that** admin's entry (otherwise reject on the next request). This binds the IP to the identity, so landing on admin A's home IP doesn't let an attacker sign in as admin B.

## Settings

Read at `SettingsScope::ADMIN`:

| Path | Type |
|---|---|
| `ip_whitelist.enabled` | bool |
| `ip_whitelist.global_cidrs` | list of CIDR strings |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        admin:
            ip_whitelist.enabled: false
            ip_whitelist.global_cidrs: []
```

The lists live in your settings store so operators change them at runtime without redeploying. For pure per-admin enforcement with no team-wide allow, put `0.0.0.0/0` and `::/0` in the global list as an explicit "team-wide layer intentionally open; only per-admin entries restrict access".

> **Operator note.** Enabling the feature with an empty global list **and** no per-admin entry covering your IP locks every admin out. Configure at least one matching CIDR before enabling, or recover by flipping `ip_whitelist.enabled` back to `false` directly in your settings store. Also configure `framework.trusted_proxies` behind a load balancer so `Request::getClientIp()` returns the real client IP.

## When IP whitelist is the right tool

Network-bound — it only helps when admins reach the panel from a predictable IP range (corporate LAN with a known public IP, a VPN exiting to a fixed CIDR, a cloud admin host with a static address). It is **not** right when admins log in from rotating home IPs (PPPoE / DHCP), mobile data behind CG-NAT, or arbitrary travel networks — they lock themselves out the moment their ISP rotates the lease. For those, leave it off and rely on the identity-bound controls this bundle also ships (2FA, passkeys, account lockout, rate limiting), which follow the user rather than the network. IP whitelist is defense-in-depth on fixed-network setups, not a replacement for those factors.
