<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

class SocialAccountsOverviewController implements SocialAccountsOverviewControllerInterface
{
    public function __construct(
        protected Environment $twig,
        protected string $template,
    ) {
    }

    public function __invoke(): Response
    {
        return new Response($this->twig->render($this->template));
    }
}
