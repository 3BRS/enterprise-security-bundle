<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Passkey;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\AbstractPasskeyAssertionVerifier;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionResultInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyCredentialRecordInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyCredentialRepositoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyValidatorFactoryInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\SessionPasskeyOptionsStorageInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

#[CoversClass(AbstractPasskeyAssertionVerifier::class)]
class AbstractPasskeyAssertionVerifierTest extends TestCase
{
    public function testSuccessfulAssertionWritesBackTheCheckedSourceAndResolvesTheUser(): void
    {
        $recorder = new \ArrayObject();
        $stored = $this->storedCredential($recorder);

        $verifier = $this->makeVerifier($recorder, storedCredential: $stored);

        $result = $verifier->verify('{"id":"cred"}', 'example.com');

        self::assertSame('passkey-user', $result->getUser()->getUserIdentifier());
        // The counter the library returned has to be persisted, and persisted before the
        // caller gets the result — otherwise a replayed assertion passes the check twice.
        self::assertSame([
            'checked' => true,
        ], $recorder['credentialSource']);
        self::assertEquals(new \DateTimeImmutable('@1700000000'), $recorder['lastUsedAt']);
        self::assertSame(1, $recorder['commits']);
    }

    public function testConsumesTheOptionsUnderTheSubclassSessionKey(): void
    {
        $recorder = new \ArrayObject();
        $verifier = $this->makeVerifier($recorder);

        $verifier->verify('{"id":"cred"}', 'example.com');

        self::assertSame('passkey_assertion_options', $recorder['consumedKey']);
    }

    public function testRejectsWhenNoCeremonyIsInProgress(): void
    {
        $verifier = $this->makeVerifier(new \ArrayObject(), serializedOptions: null);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('No passkey assertion ceremony in progress.');
        $verifier->verify('{"id":"cred"}', 'example.com');
    }

    public function testRejectsAResponseThatIsNotAnAssertion(): void
    {
        // A registration response replayed against the login endpoint must not reach the
        // assertion validator.
        $credential = PublicKeyCredential::create(
            'public-key',
            'raw-id',
            $this->createStub(AuthenticatorAttestationResponse::class),
        );

        $verifier = $this->makeVerifier(new \ArrayObject(), credential: $credential);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Expected AuthenticatorAssertionResponse from client.');
        $verifier->verify('{"id":"cred"}', 'example.com');
    }

    public function testRejectsAnUnknownCredential(): void
    {
        $verifier = $this->makeVerifier(new \ArrayObject(), storedCredential: false);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Passkey credential not recognized.');
        $verifier->verify('{"id":"cred"}', 'example.com');
    }

    /**
     * @param \ArrayObject<string, mixed> $recorder
     */
    protected function storedCredential(\ArrayObject $recorder): PasskeyCredentialRecordInterface
    {
        $stored = $this->createStub(PasskeyCredentialRecordInterface::class);
        $stored->method('getCredentialSource')->willReturn([
            'stored' => true,
        ]);
        $stored->method('setCredentialSource')->willReturnCallback(
            static function (array $source) use ($recorder): void {
                $recorder['credentialSource'] = $source;
            },
        );
        $stored->method('setLastUsedAt')->willReturnCallback(
            static function (?\DateTimeImmutable $lastUsedAt) use ($recorder): void {
                $recorder['lastUsedAt'] = $lastUsedAt;
            },
        );

        return $stored;
    }

    /**
     * @param \ArrayObject<string, mixed>                $recorder
     * @param PasskeyCredentialRecordInterface|null|false $storedCredential null builds a
     *                                                                     default record, false means "repository finds nothing"
     */
    protected function makeVerifier(
        \ArrayObject $recorder,
        ?string $serializedOptions = 'serialized-options',
        ?PublicKeyCredential $credential = null,
        PasskeyCredentialRecordInterface|null|false $storedCredential = null,
    ): AbstractPasskeyAssertionVerifier {
        $credential ??= PublicKeyCredential::create(
            'public-key',
            'raw-id',
            $this->createStub(AuthenticatorAssertionResponse::class),
        );

        if ($storedCredential === null) {
            $storedCredential = $this->storedCredential($recorder);
        }

        $repository = $this->createStub(PasskeyCredentialRepositoryInterface::class);
        $repository->method('findOneByCredentialId')->willReturn($storedCredential === false ? null : $storedCredential);

        $sessionStorage = $this->createStub(SessionPasskeyOptionsStorageInterface::class);
        $sessionStorage->method('consume')->willReturnCallback(
            static function (string $key) use ($recorder, $serializedOptions): ?string {
                $recorder['consumedKey'] = $key;

                return $serializedOptions;
            },
        );

        $source = $this->credentialSource();

        $serializer = $this->createStub(PasskeyWebauthnSerializerInterface::class);
        $serializer->method('deserialize')->willReturnCallback(
            static fn (string $payload, string $type): object => $type === PublicKeyCredentialRequestOptions::class
                ? PublicKeyCredentialRequestOptions::create('challenge')
                : $credential,
        );
        $serializer->method('denormalize')->willReturn($source);
        $serializer->method('normalize')->willReturn([
            'checked' => true,
        ]);

        $validator = $this->createStub(AuthenticatorAssertionResponseValidator::class);
        $validator->method('check')->willReturn($source);

        $validatorFactory = $this->createStub(PasskeyValidatorFactoryInterface::class);
        $validatorFactory->method('createAssertionValidator')->willReturn($validator);

        $clock = $this->createStub(ClockInterface::class);
        $clock->method('now')->willReturn(new \DateTimeImmutable('@1700000000'));

        return new class($repository, $sessionStorage, $serializer, $validatorFactory, $clock, $recorder) extends AbstractPasskeyAssertionVerifier {
            /**
             * @param \ArrayObject<string, mixed> $recorder
             */
            public function __construct(
                PasskeyCredentialRepositoryInterface $credentialRepository,
                SessionPasskeyOptionsStorageInterface $sessionStorage,
                PasskeyWebauthnSerializerInterface $serializer,
                PasskeyValidatorFactoryInterface $validatorFactory,
                ClockInterface $clock,
                protected \ArrayObject $recorder,
            ) {
                parent::__construct($credentialRepository, $sessionStorage, $serializer, $validatorFactory, $clock);
            }

            protected function getOptionsSessionKey(): string
            {
                return 'passkey_assertion_options';
            }

            protected function resolveUser(PasskeyCredentialRecordInterface $credential): UserInterface
            {
                return new TestUser('passkey-user');
            }

            protected function createResult(UserInterface $user): PasskeyAssertionResultInterface
            {
                return new class($user) implements PasskeyAssertionResultInterface {
                    public function __construct(
                        protected UserInterface $user,
                    ) {
                    }

                    public function getUser(): UserInterface
                    {
                        return $this->user;
                    }
                };
            }

            protected function commit(): void
            {
                $this->recorder['commits'] = ($this->recorder['commits'] ?? 0) + 1;
            }
        };
    }

    protected function credentialSource(): PublicKeyCredentialSource
    {
        // Constructed rather than ::create()'d — the inherited factory returns the
        // CredentialRecord parent, not this subclass.
        return new PublicKeyCredentialSource(
            'credential-id',
            'public-key',
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            'public-key-bytes',
            'user-handle',
            0,
        );
    }
}
