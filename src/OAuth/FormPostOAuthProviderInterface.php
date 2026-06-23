<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\OAuth;

/**
 * Marks an OAuth provider whose callback arrives as a cross-site POST
 * (`response_mode=form_post`, e.g. Apple Sign In). The framework-default `SameSite=Lax`
 * session cookie is not sent on such a request, so the OAuth state (and, for a link, the
 * initiating user) cannot be carried in the session. The initiate/callback controllers
 * fall back to a dedicated `SameSite=None; Secure; HttpOnly` single-use cookie for these
 * providers instead of the session.
 *
 * Opt-in marker — implementing it changes nothing for providers that use a normal
 * GET-redirect callback (Google, Microsoft), which keep using the session unchanged.
 */
interface FormPostOAuthProviderInterface
{
}
