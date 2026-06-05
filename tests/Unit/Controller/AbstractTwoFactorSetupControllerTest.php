<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Controller\Fixture\TestUser;
use ThreeBRS\EnterpriseSecurityBundle\Controller\AbstractTwoFactorSetupController;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\QrCodeGeneratorInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TotpSecretGeneratorInterface;
use Twig\Environment;

#[CoversClass(AbstractTwoFactorSetupController::class)]
class AbstractTwoFactorSetupControllerTest extends TestCase
{
    public function testRedirectsToLoginForNonAcceptableUser(): void
    {
        $controller = $this->makeController(acceptUser: false);

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/login', $response->getTargetUrl());
    }

    public function testRendersManagePageWhenAlreadyEnabled(): void
    {
        $controller = $this->makeController(alreadyEnabled: true);

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<manage/>', $response->getContent());
    }

    public function testRendersSetupFormOnGet(): void
    {
        $form = $this->createStub(FormInterface::class);
        $form->method('isSubmitted')->willReturn(false);
        $form->method('createView')->willReturn($this->createStub(FormView::class));

        $controller = $this->makeController(form: $form);

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(Response::class, $response);
        self::assertSame('<setup/>', $response->getContent());
    }

    public function testOverriddenGettersTakePrecedenceOverConstructorValues(): void
    {
        // Constructor passes enabled=true / count=10 — subclass override flips
        // enabled to false at runtime, so the manage view sees recovery codes
        // as disabled even though the cached constructor value disagrees.
        // Ensures the plugin pattern (read settings runtime via getter
        // override) is honoured by `__invoke`.
        $captured = [];
        $controller = $this->makeController(
            alreadyEnabled: true,
            overrideEnabled: false,
            templateCapture: $captured,
        );

        $response = $controller($this->requestWithSession());

        self::assertInstanceOf(Response::class, $response);
        self::assertFalse($captured['recovery_codes_enabled']);
    }

    protected function requestWithSession(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }

    /**
     * @param FormInterface<mixed>|null $form
     * @param array<string, mixed>      $templateCapture
     */
    protected function makeController(
        bool $acceptUser = true,
        bool $alreadyEnabled = false,
        ?FormInterface $form = null,
        ?bool $overrideEnabled = null,
        ?int $overrideCount = null,
        array &$templateCapture = [],
    ): AbstractTwoFactorSetupController {
        $token = $this->createStub(TokenInterface::class);
        $token->method('getUser')->willReturn(new TestUser());

        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        $tokenStorage->method('getToken')->willReturn($token);

        $totp = $this->createStub(TotpSecretGeneratorInterface::class);
        $totp->method('generateSecret')->willReturn('SECRET');
        $totp->method('buildProvisioningUri')->willReturn('otpauth://totp/x');
        $totp->method('verifyCode')->willReturn(false);

        $qr = $this->createStub(QrCodeGeneratorInterface::class);
        $qr->method('generateDataUri')->willReturn('data:image/png;base64,XXX');

        $recovery = $this->createStub(RecoveryCodeGeneratorInterface::class);

        $router = $this->createStub(RouterInterface::class);
        $router->method('generate')->willReturn('/login');

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturnCallback(static function (string $template, array $context = []) use (&$templateCapture): string {
            $templateCapture = $context;

            return $template === '@Foo/manage.html.twig' ? '<manage/>' : '<setup/>';
        });

        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturn('invalid');

        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('getToken')->willReturn(new CsrfToken('id', 'token-value'));

        $form ??= $this->createStub(FormInterface::class);

        return new class($tokenStorage, $totp, $qr, $recovery, $router, $twig, $translator, $csrf, 'Example', true, 10, $acceptUser, $alreadyEnabled, $form, $overrideEnabled, $overrideCount) extends AbstractTwoFactorSetupController {
            /**
             * @param FormInterface<mixed> $form
             */
            public function __construct(
                TokenStorageInterface $tokenStorage,
                TotpSecretGeneratorInterface $totp,
                QrCodeGeneratorInterface $qr,
                RecoveryCodeGeneratorInterface $recovery,
                RouterInterface $router,
                Environment $twig,
                TranslatorInterface $translator,
                CsrfTokenManagerInterface $csrf,
                string $issuer,
                bool $recoveryEnabled,
                int $recoveryCount,
                protected bool $acceptUser,
                protected bool $alreadyEnabled,
                protected FormInterface $form,
                protected ?bool $overrideEnabled,
                protected ?int $overrideCount,
            ) {
                parent::__construct($tokenStorage, $totp, $qr, $recovery, $router, $twig, $translator, $csrf, $issuer, $recoveryEnabled, $recoveryCount);
            }

            protected function isRecoveryCodesEnabled(): bool
            {
                return $this->overrideEnabled ?? parent::isRecoveryCodesEnabled();
            }

            protected function getRecoveryCodesCount(): int
            {
                return $this->overrideCount ?? parent::getRecoveryCodesCount();
            }

            protected function isAcceptableUser(UserInterface $user): bool
            {
                return $this->acceptUser;
            }

            protected function isTwoFactorAlreadyEnabled(UserInterface $user): bool
            {
                return $this->alreadyEnabled;
            }

            protected function getUsernameForProvisioning(UserInterface $user): string
            {
                return 'user@example.com';
            }

            protected function createVerifyForm(): FormInterface
            {
                return $this->form;
            }

            protected function enableTwoFactorAndPersistRecoveryCodes(UserInterface $user, string $secret, array $plainCodes): void
            {
            }

            protected function getLoginUrl(): string
            {
                return '/login';
            }

            protected function getSetupTemplate(): string
            {
                return '@Foo/setup.html.twig';
            }

            protected function getManageTemplate(): string
            {
                return '@Foo/manage.html.twig';
            }

            protected function getRecoveryCodesDisplayUrl(): string
            {
                return '/recovery';
            }

            protected function getPendingSecretSessionKey(): string
            {
                return 'pending_secret';
            }

            protected function getPlainRecoveryCodesSessionKey(): string
            {
                return 'plain_codes';
            }

            protected function getDisableCsrfTokenId(): string
            {
                return 'disable_csrf';
            }

            protected function getRegenerateCsrfTokenId(): string
            {
                return 'regen_csrf';
            }
        };
    }
}
