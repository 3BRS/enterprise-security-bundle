# Configuration

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle reads a small amount of configuration from your Symfony container. Most of it is optional — only the features you enable need their parameters defined.

## 1. Rate-limiter cache pool (auto-configured)

The bundle pre-configures a dedicated cache pool `three_brs.rate_limiter.cache_pool` (backed by `cache.app`) and the `three_brs.rate_limiter.storage` service. **No action required** for the default setup.

If you need a non-default backend (Redis / Memcached for clustered deployments), override the pool in your `config/packages/framework.yaml`:

```yaml
framework:
    cache:
        pools:
            three_brs.rate_limiter.cache_pool:
                adapter: cache.adapter.redis
                provider: '%env(REDIS_DSN)%'
```

## 2. Settings store

The bundle's settings infrastructure (feature toggles, policies) reads from a `SettingsProviderInterface` and writes through a `SettingsWriterInterface`. You provide the concrete implementations (typically Doctrine-backed). The bundle ships interfaces only:

```php
namespace App\Security\Settings;

use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class DbSettingsProvider implements SettingsProviderInterface
{
    public function __construct(private DbConnection $db) {}

    public function get(string $path, SettingsScope $scope): mixed { /* ... */ }
    public function getBool(string $path, SettingsScope $scope): bool { /* ... */ }
    public function getInt(string $path, SettingsScope $scope): int { /* ... */ }
    public function getNullableInt(string $path, SettingsScope $scope): ?int { /* ... */ }
    public function getString(string $path, SettingsScope $scope): string { /* ... */ }
    public function refresh(): void { /* invalidate any in-memory cache */ }
}
```

`SettingsScope` is an enum with three cases: `CUSTOMER`, `ADMIN`, `GLOBAL`. The same setting key can have different values per scope (e.g. customer lockout threshold = 5 attempts, admin = 3).

Then alias the bundle interface to your impl:

```yaml
services:
    App\Security\Settings\DbSettingsProvider: ~

    ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface:
        alias: App\Security\Settings\DbSettingsProvider
```

(A full Doctrine-backed reference impl is in [Interface implementations](interface-implementations.md).)

## 3. Feature flags (compile-time defaults)

Define your default settings via the bundle's `YamlConfigDefaultsProvider`:

```yaml
services:
    ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults\YamlConfigDefaultsProvider:
        arguments:
            $defaults: '%three_brs.security_settings.defaults%'
```

Set the `three_brs.security_settings.defaults` parameter (a `scope => path => value` map) in your kernel extension or `services.yaml`. You can write it directly, or assemble it from a structured config array with the bundle's `SettingsDefaultsBuilder`, which flattens a per-feature/per-scope tree into the flat map `YamlConfigDefaultsProvider` expects.

## 4. Required scalar parameters

The bundle's `services.yaml` reads a handful of scalar parameters directly. Define them in your `services.yaml` `parameters:` block:

```yaml
parameters:
    # Passkey — relying-party identity (bound to credentials at registration; do not change at runtime)
    three_brs.passkey.rp_id: 'example.com'
    three_brs.passkey.rp_name: 'Example App'

    # OAuth — deployment-time secrets
    three_brs.oauth.customer.google.client_id: '%env(GOOGLE_CLIENT_ID)%'
    three_brs.oauth.customer.google.client_secret: '%env(GOOGLE_CLIENT_SECRET)%'
    three_brs.oauth.customer.microsoft.client_id: '%env(MICROSOFT_CLIENT_ID)%'
    three_brs.oauth.customer.microsoft.client_secret: '%env(MICROSOFT_CLIENT_SECRET)%'
    three_brs.oauth.customer.microsoft.tenant: 'common'
    # … plus Apple if used; admin variants if you have a separate admin firewall
```

Two more parameters are not read by the bundle directly but typically belong in the same block because your wiring depends on them:

- `three_brs.passkey.skip_2fa_when_user_verified` — passed through the **subclass** constructor of `AbstractPasskeyLoginVerifyController` (see [Controllers](controllers.md)). You define the parameter and reference it as `'%three_brs.passkey.skip_2fa_when_user_verified%'` in the controller's service definition.
- `three_brs.two_factor.issuer` — used to configure **`scheb/2fa-bundle`** (the bundle's 2FA dependency), e.g. via `prepend()` in your extension when wiring `scheb_two_factor.totp.issuer`. The bundle controllers themselves do not read it.
