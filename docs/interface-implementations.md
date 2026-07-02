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

Heavier example because the WebAuthn ceremony involves multiple bundle services. A complete skeleton:

```php
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

class PasskeyAssertionVerifier implements PasskeyAssertionVerifierInterface
{
    public function __construct(
        protected SessionPasskeyOptionsStorageInterface $sessionStorage, // bundle
        protected PasskeyWebauthnSerializerInterface $serializer,        // bundle
        protected PasskeyValidatorFactoryInterface $validatorFactory,    // bundle
        protected UserPasskeyCredentialRepository $repo,                 // your repo
        protected EntityManagerInterface $em,                            // your EM
        protected ClockInterface $clock,
    ) {}

    public function verify(string $credentialResponseJson, string $host): PasskeyAssertionResultInterface
    {
        // 1. Read + consume the pending ceremony options the options endpoint stored
        //    (same session key the options builder wrote them under).
        $serializedOptions = $this->sessionStorage->consume(self::ASSERTION_OPTIONS_KEY)
            ?? throw new \RuntimeException('No passkey assertion ceremony in progress.');

        // 2. Deserialize the stored options and the browser's credential response.
        $options    = $this->serializer->deserialize($serializedOptions, PublicKeyCredentialRequestOptions::class);
        $credential = $this->serializer->deserialize($credentialResponseJson, PublicKeyCredential::class);

        $response = $credential->response;
        if (!$response instanceof AuthenticatorAssertionResponse) {
            throw new \RuntimeException('Expected an assertion response from the client.');
        }

        // 3. Look up the stored credential by its raw id; rebuild its source object.
        $stored = $this->repo->findOneByCredentialId($credential->rawId)
            ?? throw new \RuntimeException('Unknown credential.');
        $source = $this->serializer->denormalize($stored->getCredentialSource(), PublicKeyCredentialSource::class);

        // 4. Run the WebAuthn assertion check (signature, RP id, sign-count, …); returns the updated source.
        $updatedSource = $this->validatorFactory->createAssertionValidator()->check(
            $source, $response, $options, $host, $source->userHandle,
        );

        // 5. Persist the bumped sign-count + lastUsedAt — flush here, atomic with the check,
        //    to close the replay window between concurrent assertions.
        $stored->setCredentialSource($this->serializer->normalize($updatedSource));
        $stored->setLastUsedAt($this->clock->now());
        $this->em->flush();

        return new PasskeyAssertionResult($stored->getUser());
    }
}
```

`PasskeyAssertionResult` is a small DTO you write implementing `PasskeyAssertionResultInterface` (`getUser()`). `ASSERTION_OPTIONS_KEY` is the session key your options endpoint stored the ceremony under via `SessionPasskeyOptionsStorageInterface::store()`. `$stored->getUser()` is your credential entity's owner accessor — the bundle's `PasskeyCredentialRecordInterface` covers credential data only (id, source, label, timestamps), not the user association, so expose the owner on your own entity.
