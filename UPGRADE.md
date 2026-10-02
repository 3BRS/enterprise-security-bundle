# Upgrade

## 1.0 → 1.1

1. **Add `getCreatedAt()` to your password-expiration user entities.**
   `PasswordExpiration{Shop,Admin}UserInterface` now require
   `public function getCreatedAt(): ?\DateTimeInterface;` — used as the
   expiration fallback. Most entities already expose a `createdAt`.

2. **Magic-link and passkey now bypass 2FA.** They authenticate directly; 2FA
   guards plain password login only. Review against your security policy.

3. **Update verify-controller constructors** — drop the removed arguments from
   your subclasses and service definitions:
   - `AbstractMagicLinkVerifyController`: removed `$eventDispatcher`, `$twoFactorHandler`.
   - `AbstractPasskeyLoginVerifyController`: removed `$eventDispatcher`, `$twoFactorHandler`, `$skipTwoFactorWhenUserVerified`.

4. **Remove the parameter** `three_brs.passkey.skip_2fa_when_user_verified`.

5. **`PasskeyAssertionResultInterface::isUserVerified()` is gone** — only
   `getUser()` is required now.

## 1.1 → 2.0

1. **Password-login control is now scope-wide, not per-user.** If you extended
   `AbstractPasswordLoginCheckListener`:
   - Rename your `isFeatureEnabled()` override to `isPasswordLoginEnabled()` and invert its
     meaning: return `true` when password login is **allowed** for the scope. (Previously the
     base gated on `isFeatureEnabled()` and then a per-user `isPasswordLoginAllowedForUser()`
     lookup; now the single hook decides.)
   - Drop the `PasswordLoginPreferenceRepositoryInterface` constructor argument from your
     subclass and its service definition — the base constructor is gone.
   - `PasswordLoginPreferenceInterface` and `PasswordLoginPreferenceRepositoryInterface` are
     removed; delete your implementations (and the per-user preference storage if it served
     no other purpose).
   - Rename the settings key `password_login_control` → `password_login` wherever you set
     defaults or read the toggle (e.g. `password_login.enabled`).

2. **OAuth confirm-link is now challenge-based, not password-based.** If you extended
   `AbstractOAuthConfirmLinkController`:
   - The matched account no longer needs to be a `PasswordAuthenticatedUserInterface` —
     passwordless accounts can complete confirm-link once you implement a challenge.
   - Drop the `UserPasswordHasherInterface $passwordHasher` argument from your subclass
     constructor and its service definition — the base constructor is now
     `($tokenStorage, $router, $twig, $logger)`; remove any `$this->passwordHasher` usage.
   - Implement `prepareChallenge(UserInterface $user, array $pending, Request $request): void`
     — issue the ownership proof on the initial GET (e.g. generate a one-time code, email it,
     persist its hash + expiry). Make it idempotent so a refresh does not re-send.
   - Implement `verifyChallenge(UserInterface $user, array $pending, Request $request): ?string`
     — validate the submitted proof on POST (read your own field, e.g. `_code`, instead of the
     old `_password`); return `null` on success or a translation key on failure.
   - Update your confirm-link template/form: stop submitting `_password`, submit whatever
     `verifyChallenge()` reads, and define/translate your own failure key — the base no longer
     emits `three_brs.ui.social_login.invalid_password`.
   - (Optional) The bundle ships both halves of a code-based challenge, so you don't re-implement
     the security logic: `OAuthLinkCodeGenerator` mints the 6-digit code and SHA-256-hashes it
     (use in `prepareChallenge`); `CodeChallengeValidator` runs the verify — expiry + attempt
     limit + single-use + constant-time compare — returning a verdict plus the next challenge
     state to persist (use in `verifyChallenge`). Reference both by their concrete service ids;
     there is no interface alias for autowiring.

3. **OAuth cross-site `form_post` providers (Apple) now use a signed state cookie.** If you
   extended the OAuth initiate/callback controllers:
   - Wire the bundle's `StateCookieSigner` service (registered with `$secret: '%kernel.secret%'`,
     so the cookie's integrity relies on a strong, secret `APP_SECRET` — as the rest of Symfony
     security already does) into both subclasses' service definitions:
     `AbstractOAuthInitiateController` gained a `StateCookieSignerInterface` constructor argument
     (plus an optional `Security`), and `AbstractOAuthCallbackController` gained a
     `StateCookieSignerInterface` argument.
   - Implement `findUserByIdentifier(string $identifier): ?UserInterface` on your callback
     subclass (typically `$userProvider->loadUserByIdentifier($identifier)`) — it recovers the
     link-initiating user from the verified cookie on a cross-site callback.
   - Mark any provider whose callback is a cross-site `form_post` (e.g. Apple) with
     `FormPostOAuthProviderInterface`.

## 2.0 → 2.1

1. **The controllers that sign a user in outside the firewall now enforce the account state.** If you
   extended `AbstractMagicLinkVerifyController`, `AbstractPasskeyLoginVerifyController`,
   `AbstractOAuthCallbackController`, `AbstractOAuthConfirmLinkController` or
   `AbstractTwoFactorRecoveryChallengeController`:
   - Add `Symfony\Component\Security\Core\User\UserCheckerInterface $userChecker` as the **last
     constructor argument** of your subclass, forward it to `parent::__construct()`, and pass it as
     `$userChecker` in each of their service definitions in your `services.yaml`.
   - Bind a checker that refuses on the **account state alone** — one that throws `DisabledException`
     for an account that may not sign in, and nothing else. Do **not** pass your firewall's checker
     chain: it must not throw `LockedException` (an account locked by failed password attempts has to
     keep its passwordless way in, otherwise anyone can lock a victim out of their own passkey by
     guessing their password wrong often enough) nor `CredentialsExpiredException` (an expired
     password must not close the routes its owner needs to recover). The bundle ships no such checker
     — "enabled" belongs to your model, not to Symfony's `UserInterface` — so write a
     `UserCheckerInterface` over your own flag. The wiring is spelled out in
     `docs/security-configuration.md`.
   - Translate `three_brs.account_state.sign_in_refused` — the key the controllers flash when they
     turn a refused account away. (The passkey verify endpoint answers `403` instead; it is consumed
     by a `fetch()`, not rendered.)

2. **Name your own redundant password-length message.** `PasswordPolicyFilteringValidator` used to
   drop one hard-coded framework message key when the bundle's password policy had already reported
   on the same field; it now drops only what you name in the new parameter
   `three_brs.password_policy.redundant_message_templates` (empty by default). Add it to the
   `parameters:` block of your `services.yaml` — without it a too-short password is reported twice,
   once in your own wording and once by the policy. Symfony's `Length` constraint is still recognised
   without configuration.

3. **Account-deletion confirmation is now a hook, not a hard-coded password check.** If you extended
   `AbstractAccountDeletionRequestController`:
   - Nothing to do if your form keeps its `currentPassword` field — the default
     `isDeletionConfirmed(FormInterface $form, UserInterface $user): bool` behaves exactly as before.
   - If your accounts have no password to confirm with (created by a social sign-up, or with password
     sign-in turned off), override `isDeletionConfirmed()` with the confirmation you do have instead
     of dropping re-authentication; the default now returns `false` (rather than throwing) when the
     form carries no password field.
   - Override the `NOT_CONFIRMED_MESSAGE` constant if `three_brs.account_deletion.invalid_password`
     no longer describes what failed.

## 2.1 → 2.2

1. **`StateCookieSigner` now bounds the lifetime of what it signs, and takes two new constructor
   arguments.** If you register it yourself (rather than relying on the bundle's `services.yaml`),
   add `$clock` and optionally `$ttl`:

   ```yaml
   ThreeBRS\EnterpriseSecurityBundle\OAuth\StateCookieSigner:
       arguments:
           $secret: '%kernel.secret%'
           $clock: '@clock'   # any psr/clock implementation
           $ttl: 600          # seconds; must cover the OAuth round-trip at the provider
   ```

   Keep `$ttl` in step with `AbstractOAuthInitiateController::STATE_COOKIE_LIFETIME`. The signer is
   the authority — the cookie attribute is only a hint to the browser — so if the two drift, a value
   the browser still holds may be refused and the user simply restarts the sign-in.

2. **State cookies issued before the upgrade stop being accepted.** They carry no signed expiry, and
   the check fails closed rather than granting them their previous unlimited lifetime. The practical
   effect is that anyone *mid* Apple sign-in across the deploy gets "Invalid OAuth state parameter."
   and clicks the button again; the window is one OAuth round-trip and nothing is lost. No action
   required — only affects providers marked `FormPostOAuthProviderInterface` (of the bundled ones,
   Apple).

## 2.2 → 2.2.2

Nothing is required — every change is backwards compatible. Two of them are worth a look:

1. **The bundle now ships English translation catalogues**
   (`src/Resources/translations/{validators,flashes,messages}.en.yaml`) covering every message id it
   emits. Symfony picks up a bundle's translation directory on its own, so ids you had left
   undefined — which rendered as the raw `three_brs.*` string — now read as English sentences.

   Your own wording still wins: the app's `translations/` directory is loaded after every bundle,
   and so is any bundle registered after this one in `config/bundles.php` (where
   `3brs/sylius-enterprise-security-plugin` sits). Only English ships; add the other locales you
   serve. The catalogues assume the `flashes` domain for flash ids and the default `messages`
   domain for the two recovery-challenge ids handed to your template — see
   [Templates & translations](docs/templates-and-translations.md#translation-domains) if you render
   them elsewhere. Loading them needs `symfony/translation` plus `symfony/yaml` (its YAML loader),
   both already present in a full-stack Symfony app; without them the files are simply inert.

2. **`AbstractOAuthCallbackController` flashes a translation key when the provider call fails**,
   instead of the exception's message. If you render OAuth flashes without translating them, define
   `three_brs.ui.social_login.provider_error` in the domain you render flashes in (the shipped
   `flashes.en.yaml` has an English default) — otherwise the user now sees the raw key.

   The detail is not lost: it goes to the logger at `warning` under
   `{your audit channel}.provider_error`, with the exception attached. It was developer-facing text
   — for a failed profile fetch it can quote the provider's raw response body — and the other
   failures on that path (`Invalid OAuth state parameter.`, `Missing authorization code in Google
   callback.`) told the person reading them nothing they could act on.

## 2.2.2 → 2.3.0

Nothing is required — the release is additive. Two new abstracts are available if you want to drop
your own copies of the same logic:

1. **`AbstractPasskeyAssertionVerifier`** replaces a hand-written `PasskeyAssertionVerifierInterface`
   implementation. Extend it, pass its five collaborators to `parent::__construct()`, and implement
   `getOptionsSessionKey()`, `resolveUser()`, `createResult()` and `commit()`. Your existing class
   keeps working untouched — the interface is unchanged. The worked example is in
   [Interface implementations](docs/interface-implementations.md#reference-impl-passkey-assertion-verifier).

   One thing to check while switching: the flush belongs in `commit()`, i.e. inside the verifier. If
   your controller flushed after calling `verify()`, move it — the sign-count write has to be atomic
   with the WebAuthn check, or two concurrent assertions replaying the same response both pass.

2. **`AbstractNewDeviceDetector`** replaces the "is this device new?" service behind login
   notifications, and `KnownDeviceRecordInterface` types the row it writes. Your known-device table
   wants a **unique key over (user, fingerprint)** — the abstract settles a concurrent sign-in by
   catching the insert conflict (`isConcurrentInsertConflict()`), which is what keeps a user from
   getting two "new device" mails for one sign-in. Without the constraint it still works, it just
   loses that protection.

## 2.3.0 → 2.4.0

1. **Linking an OAuth account needs a full sign-in** (`IS_AUTHENTICATED_FULLY`). A sign-in that waits
   for its two-factor code could link a provider account and so get past the code; that is closed in
   `AbstractOAuthInitiateController` and `AbstractOAuthCallbackController` themselves.
   - Pass the `Security` constructor argument to your `AbstractOAuthInitiateController` subclass
     (`$security: '@security.helper'`) if you have not: without it every `intent=link` now ends in an
     `AccessDeniedException`.
   - A user signed in through a remember-me cookie who starts a link is sent to the sign-in page; the
     firewall saves the link as the target path, which the default success handler returns them to.
     To let them link without signing in again, override `isLinkAllowed()` in both subclasses with
     `AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED`, which a sign-in waiting for its two-factor code
     does not satisfy either.
   - If you closed the hole yourself — `isAcceptableCurrentUser()` refusing a `TwoFactorTokenInterface`
     in your callback subclass, `createStateCookie()` leaving the user out for one in your initiate
     subclass — the overrides can go.
   - With 2FA on the firewall, the OAuth routes can have `PUBLIC_ACCESS`, so that a user on the code
     page can sign in with a provider instead; see
     [Security configuration](docs/security-configuration.md#oauth).

2. **`TwoFactorAwareAuthenticationSuccessHandler` now forwards the firewall's `form_login` options**
   (`default_target_path`, `use_referer`, …) and its name to the wrapped handler, so a user who signs
   in without a 2FA challenge lands where the firewall says instead of on `/`. Nothing to change in
   `security.yaml`. If you subclassed the handler only to forward them yourself, the subclass can go.
   If your service definition passes `security.authentication.success_handler.<firewall>.form_login`
   as `$defaultSuccessHandler`, replace it with a `DefaultAuthenticationSuccessHandler` service of
   your own — see the [two-factor guide](docs/features/two-factor-authentication.md#scheb-wiring).

3. **Optional: end a sign-in that waits for its two-factor code when the user leaves the code page.**
   Nothing changes until you wire `PendingSignInCanceller` and `CancelPendingSignInRequiredHandler`
   for a firewall — see
   [Leaving the code page](docs/features/two-factor-authentication.md#leaving-the-code-page). If you
   built the same thing in your app, it can go once these are wired.
