<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyAssertionOptionsBuilderInterface;
use ThreeBRS\EnterpriseSecurityBundle\Passkey\PasskeyWebauthnSerializerInterface;

class PasskeyLoginOptionsController implements PasskeyLoginOptionsControllerInterface
{
    public function __construct(
        protected PasskeyAssertionOptionsBuilderInterface $optionsBuilder,
        protected PasskeyWebauthnSerializerInterface $serializer,
        protected bool $enabled,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (! $this->enabled) {
            throw new NotFoundHttpException();
        }

        $options = $this->optionsBuilder->build();

        return JsonResponse::fromJsonString($this->serializer->serialize($options));
    }
}
