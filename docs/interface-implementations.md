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
| `FormPostOAuthProviderInterface` *(marker)* | Only on a provider whose callback is a cross-site `form_post` (e.g. Apple — already marked) | No methods — opt-in marker; makes the OAuth controllers carry the `state` in a dedicated `SameSite=None; Secure; HttpOnly`, HMAC-signed single-use cookie (signed by `StateCookieSigner`) that survives the cross-site POST and is tamper-proof, instead of the session |

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
        return $this->cache[$key] ?? $this->defaults->get($path, $scope);
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

The ceremony itself lives in the bundle — extend `AbstractPasskeyAssertionVerifier` and bind the four
things it cannot know:

```php
use ThreeBRS\EnterpriseSecurityBundle\Passkey\AbstractPasskeyAssertionVerifier;

class PasskeyAssertionVerifier extends AbstractPasskeyAssertionVerifier implements PasskeyAssertionVerifierInterface
{
    public function __construct(
        UserPasskeyCredentialRepository $repo,                    // your repo, typed as the bundle interface
        SessionPasskeyOptionsStorageInterface $sessionStorage,    // bundle
        PasskeyWebauthnSerializerInterface $serializer,           // bundle
        PasskeyValidatorFactoryInterface $validatorFactory,       // bundle
        ClockInterface $clock,
        protected EntityManagerInterface $em,                     // your EM
    ) {
        parent::__construct($repo, $sessionStorage, $serializer, $validatorFactory, $clock);
    }

    // The session key your options endpoint stored the ceremony under, via
    // SessionPasskeyOptionsStorageInterface::store(). One per firewall, so a ceremony
    // started on the shop cannot be completed on the admin.
    protected function getOptionsSessionKey(): string
    {
        return PasskeyAssertionOptionsBuilder::SESSION_KEY;
    }

    // Your credential entity's owner accessor — `PasskeyCredentialRecordInterface` covers
    // credential data only (id, source, label, timestamps), not the user association.
    protected function resolveUser(PasskeyCredentialRecordInterface $credential): UserInterface
    {
        return $credential->getUser();
    }

    // A small DTO of yours implementing PasskeyAssertionResultInterface (`getUser()`).
    protected function createResult(UserInterface $user): PasskeyAssertionResultInterface
    {
        return new PasskeyAssertionResult($user);
    }

    protected function commit(): void
    {
        $this->em->flush();
    }
}
```

What the abstract runs, in order: consume the pending ceremony options (absent ⇒ refuse), deserialize
them and the browser's credential response, refuse anything that is not an
`AuthenticatorAssertionResponse`, look the stored credential up by its raw id (unknown ⇒ refuse),
rebuild its `PublicKeyCredentialSource`, run the WebAuthn check (signature, RP id, sign-count, …),
write the updated source and `lastUsedAt` back, and `commit()`.

**The commit belongs inside the verifier, not in your controller.** Persisting the bumped sign-count
has to be atomic with the check, or two concurrent assertions replaying the same authenticator
response both pass before either one's counter lands. That is why `commit()` is a hook rather than
something the caller does afterwards.

## Reference impl: New-device detector

Same shape, smaller surface — `AbstractNewDeviceDetector` owns the check-and-remember step behind
login notifications:

```php
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use ThreeBRS\EnterpriseSecurityBundle\Session\AbstractNewDeviceDetector;
use ThreeBRS\EnterpriseSecurityBundle\Session\KnownDeviceRecordInterface;

class NewDeviceDetector extends AbstractNewDeviceDetector
{
    public function __construct(
        protected UserKnownDeviceRepository $repository,
        protected EntityManagerInterface $em,
    ) {}

    protected function isKnownDevice(UserInterface $user, string $fingerprint): bool
    {
        return $this->repository->existsForUser($user, $fingerprint);
    }

    protected function createRecord(UserInterface $user, string $fingerprint): KnownDeviceRecordInterface
    {
        $device = new UserKnownDevice();
        $device->setUser($user);
        $device->setFingerprint($fingerprint);

        return $device;
    }

    protected function save(KnownDeviceRecordInterface $record): void
    {
        $this->em->persist($record);
        $this->em->flush();
    }

    protected function discardUnflushed(KnownDeviceRecordInterface $record): void
    {
        $this->em->detach($record);
    }

    protected function isConcurrentInsertConflict(\Throwable $exception): bool
    {
        return $exception instanceof UniqueConstraintViolationException;
    }
}
```

`checkAndRemember($user, $fingerprint)` returns true only for a device that was not on record — and
records it on the way out, so the second call for the same pair returns false. **Your table needs a
unique key over (user, fingerprint)**: that constraint is what makes a concurrent sign-in from the
same device fail its insert instead of both requests reporting a new device and emailing the user
twice. Without it the detector still works, it just loses the race protection.
