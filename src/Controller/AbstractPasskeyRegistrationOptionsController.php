<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;

abstract class AbstractPasskeyRegistrationOptionsController
{
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

        $user = $this->tokenStorage->getToken()?->getUser();
        if (! $user instanceof UserInterface || ! $this->isAcceptableUser($user)) {
            throw new AccessDeniedHttpException();
        }

        $options = $this->buildRegistrationOptions($user);

        return JsonResponse::fromJsonString($this->serializer->serialize($options));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    abstract protected function buildRegistrationOptions(UserInterface $user): PublicKeyCredentialCreationOptions;
}
