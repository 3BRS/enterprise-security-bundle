<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\AccountDeletion\CustomerDeletionRequestRepositoryInterface;
use Twig\Environment;

class AccountDeletionsListController implements AccountDeletionsListControllerInterface
{
    public function __construct(
        protected CustomerDeletionRequestRepositoryInterface $repository,
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
            'pendingRequests' => $this->repository->findPendingForAdmin(),
        ]));
    }
}
