<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\AccountDeletion;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Anonymize the personal data carried on a user entity. Implementations replace
 * identifying fields (name, email, phone, address …) with non-identifying
 * placeholders so the row can survive in the database (for foreign-key
 * integrity and business-data retention) while no longer carrying personal
 * data subject to GDPR / equivalent regulations.
 *
 * Business data tied to the user (orders, payments, audit trails) is
 * intentionally retained — the contract is "anonymize the user record itself",
 * not "delete every related row".
 *
 * The Sylius plugin's `CustomerAnonymizer` covers the Sylius-specific
 * `Customer` entity (buyer profile, separate from the auth identity). Non-Sylius
 * apps implement this interface against their own `User` entity.
 */
interface UserAnonymizerInterface
{
    public function anonymize(UserInterface $user): void;
}
