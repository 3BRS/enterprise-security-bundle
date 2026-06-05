<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;

abstract class AbstractPasskeyListController
{
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected Environment $twig,
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

        return new Response($this->twig->render($this->getTemplate(), [
            'credentials' => $this->findCredentialsForUser($user),
        ]));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    /**
     * @return iterable<object>
     */
    abstract protected function findCredentialsForUser(UserInterface $user): iterable;

    abstract protected function getTemplate(): string;
}
