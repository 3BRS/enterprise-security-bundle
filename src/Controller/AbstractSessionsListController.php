<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use ThreeBRS\EnterpriseSecurityBundle\Session\UserAgentParserInterface;
use Twig\Environment;

abstract class AbstractSessionsListController
{
    public function __construct(
        protected TokenStorageInterface $tokenStorage,
        protected UserAgentParserInterface $userAgentParser,
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

        $sessions = $this->findActiveSessionsForUser($user);
        $currentSessionId = $request->hasSession() ? $request->getSession()->getId() : '';

        $rows = [];
        foreach ($sessions as $session) {
            $rows[] = [
                'session' => $session,
                'userAgent' => $this->userAgentParser->parse($session->getUserAgent()),
                'isCurrent' => $session->getSessionId() === $currentSessionId,
            ];
        }

        return new Response($this->twig->render($this->getTemplate(), [
            'rows' => $rows,
        ]));
    }

    abstract protected function isAcceptableUser(UserInterface $user): bool;

    /**
     * @return iterable<\ThreeBRS\EnterpriseSecurityBundle\Session\SessionRecordInterface>
     */
    abstract protected function findActiveSessionsForUser(UserInterface $user): iterable;

    abstract protected function getTemplate(): string;
}
