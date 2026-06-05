# Required interface implementations

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle ships **contracts**, not implementations. For each enabled feature, you provide a concrete class and alias the bundle interface to it.

| Bundle interface | Required when | Typical impl |
|---|---|---|
| `SettingsProviderInterface` | Always (used by feature toggles, policies, all controllers' `$enabled` flag) | Doctrine repository wrapping a `SecuritySetting` entity |
| `SettingsWriterInterface` | Only if you have an admin UI to mutate settings at runtime | Doctrine `EntityManager` with optimistic locking |
| `MagicLinkTokenVerifierInterface` | If magic-link login enabled | Repository lookup by `tokenHash` + expiry/used check |
| `PasskeyAssertionVerifierInterface` | If passkey login enabled | Repository lookup by `credentialId` + WebAuthn verify via bundle's `PasskeyValidatorFactory` |
| `UserAnonymizerInterface` | If GDPR self-service account deletion enabled | Clears name / email / phone / address on the user once the grace period expires (driven by `DueDeletionsProcessorInterface`) |
| `OAuthProviderInterface` *(× N)* | Only if you add providers beyond Google/Apple/Microsoft (bundle ships those three) | Provider-specific OAuth2 client wrapper, tag with `three_brs.oauth_provider` |

## Reference impl: Settings provider (Doctrine-backed)

```php
namespace App\Security\Settings;

use App\Entity\SecuritySetting;
use App\Repository\SecuritySettingRepository;
use ThreeBRS\EnterpriseSecurityBundle\Settings\Defaults\SettingsDefaultsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsScope;

class DbSettingsProvider implements SettingsProviderInterface
{
    /** @var array<string, mixed>|null */
    protected ?array $cache = null;

    public function __construct(
        protected SecuritySettingRepository $repository,
        protected SettingsDefaultsProviderInterface $defaults,
    ) {
    }

    public function getBool(string $path, SettingsScope $scope): bool
    {
        return (bool) $this->resolve($path, $scope);
    }

    public function getInt(string $path, SettingsScope $scope): int
    {
        return (int) $this->resolve($path, $scope);
    }

    public function getNullableInt(string $path, SettingsScope $scope): ?int
    {
        $v = $this->resolve($path, $scope);
        return $v === null ? null : (int) $v;
    }

    public function getString(string $path, SettingsScope $scope): string
    {
        return (string) $this->resolve($path, $scope);
    }

    public function get(string $path, SettingsScope $scope): mixed
    {
        return $this->resolve($path, $scope);
    }

    public function refresh(): void
    {
        $this->cache = null;
    }

    protected function resolve(string $path, SettingsScope $scope): mixed
    {
        $key = $scope->value . '.' . $path;
        if ($this->cache === null) {
            $this->cache = [];
            foreach ($this->repository->findAll() as $row) {
                $this->cache[$row->getScope() . '.' . $row->getPath()] = $row->getValue();
            }
        }
        return $this->cache[$key] ?? $this->defaults->getDefaultFor($path, $scope);
    }
}
```

Then alias the bundle interface:

```yaml
services:
    App\Security\Settings\DbSettingsProvider: ~

    ThreeBRS\EnterpriseSecurityBundle\Settings\SettingsProviderInterface:
        alias: App\Security\Settings\DbSettingsProvider
```

## Reference impl: Magic-link verifier

```php
namespace App\Security\MagicLink;

use App\Repository\UserMagicLinkTokenRepository;
use Psr\Clock\ClockInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenGeneratorInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenValidatorInterface;
use ThreeBRS\EnterpriseSecurityBundle\MagicLink\MagicLinkTokenVerifierInterface;

class MagicLinkTokenVerifier implements MagicLinkTokenVerifierInterface
{
    public function __construct(
        protected UserMagicLinkTokenRepository $repository,
        protected MagicLinkTokenGeneratorInterface $generator,
        protected MagicLinkTokenValidatorInterface $validator,
    ) {
    }

    public function verify(string $plainToken): ?MagicLinkRecordInterface
    {
        $hash = $this->generator->hash($plainToken);
        $record = $this->repository->findOneByTokenHash($hash);
        if ($record === null) {
            return null;
        }
        return $this->validator->isUsable($record) ? $record : null;
    }
}
```

Bundle's `MagicLinkTokenGenerator` + `MagicLinkTokenValidator` are concrete — you reuse them. You only write the **repository lookup** glue.

## Reference impl: Passkey assertion verifier

Heavier example because WebAuthn ceremony involves multiple bundle services. See [the Sylius plugin's `CustomerPasskeyAssertionVerifier`](https://github.com/3BRS/sylius-enterprise-security-plugin/blob/main/src/Service/Passkey/CustomerPasskeyAssertionVerifier.php) for a complete ~80-line example. The skeleton:

```php
class PasskeyAssertionVerifier implements PasskeyAssertionVerifierInterface
{
    public function __construct(
        protected PasskeyValidatorFactoryInterface $validatorFactory,   // bundle
        protected PasskeyWebauthnSerializerInterface $serializer,        // bundle
        protected SessionPasskeyOptionsStorageInterface $sessionStorage, // bundle
        protected UserPasskeyCredentialRepository $repo,                 // your repo
        protected EntityManagerInterface $em,                            // your EM
        protected ClockInterface $clock,
    ) {}

    public function verify(string $credentialResponseJson, string $host): PasskeyAssertionResultInterface
    {
        // 1. Read pending options from session (set during /passkey/login/options)
        $optionsJson = $this->sessionStorage->retrieve('shop.assertion_options')
            ?? throw new \RuntimeException('No pending passkey ceremony.');

        // 2. Deserialize options + the user's response
        $options = $this->serializer->deserializeRequestOptions($optionsJson);
        $response = $this->serializer->deserializeCredential($credentialResponseJson);

        // 3. Look up the credential by ID; verify via bundle's WebAuthn validator
        $credential = $this->repo->findOneByCredentialId($response->id)
            ?? throw new \RuntimeException('Unknown credential.');

        $validator = $this->validatorFactory->build($host);
        $validatedCredential = $validator->check($response, $options, $credential->toSource(), $host);

        // 4. Update signCount + lastUsedAt, return result
        $credential->setSignCount($validatedCredential->counter);
        $credential->setLastUsedAt($this->clock->now());
        $this->em->flush();

        return new PasskeyAssertionResult($credential->getUser(), $validatedCredential->isUserVerified);
    }
}
```

`PasskeyAssertionResult` is a small DTO you write (or copy from the plugin) implementing `PasskeyAssertionResultInterface`.
