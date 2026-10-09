<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;

abstract class AbstractPasskeyRegistrationOptionsController
{
    use FullSignInGuardTrait;

    public function __construct(
        protected PasskeyWebauthnSerializerInterface $serializer,
        protected TokenStorageInterface $tokenStorage,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();
        if (! $user instanceof UserInterface || ! $this->isRegistrationAllowed($token) || ! $this->isAcceptableUser($user)) {
            throw new AccessDeniedHttpException();
        }

        $options = $this->buildRegistrationOptions($user);

        return JsonResponse::fromJsonString($this->serializer->serialize($options));
    }

    /**
     * A passkey is a way to sign in to the account that skips the second factor, so registering one
     * needs a full sign-in (FullSignInGuardTrait).
     */
    protected function isRegistrationAllowed(?TokenInterface $token): bool
    {
        return $this->isFullSignIn($token);
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function buildRegistrationOptions(UserInterface $user): PublicKeyCredentialCreationOptions;
}
