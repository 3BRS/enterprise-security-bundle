<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\Form\FormError;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\QrCodeGeneratorInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\RecoveryCodeGeneratorInterface;
use ThreeBRS\EnterpriseSecurityBundle\TwoFactor\TotpSecretGeneratorInterface;
use Twig\Environment;

abstract class AbstractTwoFactorSetupController
{
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected TotpSecretGeneratorInterface $totpGenerator,
        protected QrCodeGeneratorInterface $qrGenerator,
        protected RecoveryCodeGeneratorInterface $recoveryGenerator,
        protected RouterInterface $router,
        protected Environment $twig,
        protected TranslatorInterface $translator,
        protected CsrfTokenManagerInterface $csrfTokenManager,
        protected string $issuer,
        protected bool $recoveryCodesEnabled,
        protected int $recoveryCodesCount,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            return new RedirectResponse($this->getLoginUrl());
        }

        if ($this->isTwoFactorAlreadyEnabled($user)) {
            return new Response($this->twig->render($this->getManageTemplate(), [
                'disable_csrf_token' => $this->csrfTokenManager->getToken($this->getDisableCsrfTokenId())->getValue(),
                'regenerate_csrf_token' => $this->csrfTokenManager->getToken($this->getRegenerateCsrfTokenId())->getValue(),
                'recovery_codes_enabled' => $this->isRecoveryCodesEnabled(),
            ]));
        }

        $session = $request->getSession();
        $secret = $session->get($this->getPendingSecretSessionKey());
        if (! is_string($secret) || $secret === '') {
            $secret = $this->totpGenerator->generateSecret();
            $session->set($this->getPendingSecretSessionKey(), $secret);
        }

        $form = $this->createVerifyForm();
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $code = str_replace('-', '', (string) $form->get('code')->getData());
            if ($this->totpGenerator->verifyCode($secret, $code)) {
                $plainCodes = $this->isRecoveryCodesEnabled()
                    ? $this->recoveryGenerator->generate($this->getRecoveryCodesCount())
                    : [];

                $this->enableTwoFactorAndPersistRecoveryCodes($user, $secret, $plainCodes);

                $session->remove($this->getPendingSecretSessionKey());
                $session->set($this->getPlainRecoveryCodesSessionKey(), $plainCodes);

                return new RedirectResponse($this->getRecoveryCodesDisplayUrl());
            }

            $form->get('code')->addError(new FormError(
                $this->translator->trans('three_brs.two_factor.invalid_code', [], 'validators'),
            ));
        }

        $username = $this->getUsernameForProvisioning($user);
        $uri = $this->totpGenerator->buildProvisioningUri($secret, $username, $this->issuer);

        return new Response($this->twig->render($this->getSetupTemplate(), [
            'form' => $form->createView(),
            'qr_data_uri' => $this->qrGenerator->generateDataUri($uri),
            'secret' => $secret,
        ]));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function isTwoFactorAlreadyEnabled(UserInterface $user): bool;

    abstract protected function getUsernameForProvisioning(UserInterface $user): string;

    /**
     * @return FormInterface<mixed>
     */
    abstract protected function createVerifyForm(): FormInterface;

    /**
     * Apply the verified TOTP secret to the user entity (setTotpSecret + setTwoFactorEnabled),
     * hash + persist the plain recovery codes via the plugin's entity manager, then flush.
     *
     * @param array<int, string> $plainCodes
     */
    abstract protected function enableTwoFactorAndPersistRecoveryCodes(UserInterface $user, string $secret, array $plainCodes): void;

    abstract protected function getLoginUrl(): string;

    abstract protected function getSetupTemplate(): string;

    abstract protected function getManageTemplate(): string;

    abstract protected function getRecoveryCodesDisplayUrl(): string;

    abstract protected function getPendingSecretSessionKey(): string;

    abstract protected function getPlainRecoveryCodesSessionKey(): string;

    abstract protected function getDisableCsrfTokenId(): string;

    abstract protected function getRegenerateCsrfTokenId(): string;

    /**
     * Subclass may override to read the toggle at runtime (e.g. from DB-backed
     * settings) rather than the constructor parameter passed at compile time.
     */
    protected function isRecoveryCodesEnabled(): bool
    {
        return $this->recoveryCodesEnabled;
    }

    protected function getRecoveryCodesCount(): int
    {
        return $this->recoveryCodesCount;
    }
}
