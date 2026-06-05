<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\Lockout\LockedUserRepositoryInterface;
use Twig\Environment;

class LockedUsersListController implements LockedUsersListControllerInterface
{
    public function __construct(
        protected LockedUserRepositoryInterface $repository,
        protected Environment $twig,
        protected string $template,
        protected bool $enabled,
    ) {
    }

    public function __invoke(): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        return new Response($this->twig->render($this->template, [
            'users' => $this->repository->findAllLocked(),
        ]));
    }
}
