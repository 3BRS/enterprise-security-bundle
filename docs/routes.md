# Routes reference

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

URLs are up to you — these are the controllers and the typical HTTP verbs. Pick paths and route names that fit your app. See [Controllers](controllers.md) for how to wire each one.

| Controller (abstract) | Method | Sample path | Notes |
|---|---|---|---|
| `PasskeyLoginOptionsController` *(concrete)* | POST | `/passkey/login/options` | Returns WebAuthn assertion options JSON |
| `AbstractPasskeyLoginVerifyController` | POST | `/passkey/login/verify` | Submits credential response, completes login |
| `AbstractPasskeyRegistrationOptionsController` | POST | `/passkey/register/options` | Returns WebAuthn creation options JSON |
| `AbstractPasskeyRegistrationVerifyController` | POST | `/passkey/register/verify` | Submits credential, persists |
| `AbstractPasskeyListController` | GET | `/account/passkey` | Lists user's passkeys |
| `AbstractPasskeyDeleteController` | POST | `/account/passkey/{id}/delete` | CSRF-protected delete |
| `AbstractMagicLinkRequestController` | GET, POST | `/magic-link/request` | Renders form / dispatches email |
| `AbstractMagicLinkVerifyController` | GET | `/magic-link/verify/{token}` | Email click target |
| `AbstractOAuthInitiateController` | GET | `/oauth/{provider}` | Redirects to provider |
| `AbstractOAuthCallbackController` | GET | `/oauth/{provider}/callback` | Provider callback target |
| `AbstractOAuthConfirmLinkController` | GET, POST | `/oauth/confirm-link` | Existing-account ownership-proof challenge |
| `AbstractSocialAccountUnlinkController` | POST | `/account/social/{provider}/unlink` | CSRF-protected unlink |
| `AbstractTwoFactorSetupController` | GET, POST | `/account/two-factor` | Setup wizard / manage |
| `AbstractTwoFactorRecoveryChallengeController` | GET, POST | `/2fa/recovery` | Login completion via recovery code |
| `AbstractTwoFactorDisableController` | POST | `/account/two-factor/disable` | CSRF-protected disable |
| `AbstractTwoFactorRegenerateRecoveryCodesController` | POST | `/account/two-factor/regenerate` | CSRF-protected regenerate |
| `AbstractSessionsListController` | GET | `/account/sessions` | List active sessions |
| `AbstractSessionRevokeController` | POST | `/account/sessions/{id}/revoke` | CSRF-protected |
| `AbstractSessionRevokeOthersController` | POST | `/account/sessions/revoke-others` | CSRF-protected |
| `LockedUsersListController` *(concrete)* | GET | `/admin/locked-users` | Admin list |
| `AbstractUnlockUserController` | POST | `/admin/locked-users/{id}/unlock` | Admin CSRF-protected |
| `AbstractAccountDeletionRequestController` | GET, POST | `/account/delete` | Customer request form |
| `AccountDeletionsListController` *(concrete)* | GET | `/admin/deletions` | Admin list of pending deletions |
| `AbstractAccountDeletionCancelController` | POST | `/admin/deletions/{id}/cancel` | Admin CSRF-protected |
| `SocialAccountsOverviewController` *(concrete)* | GET | `/account/social-accounts` | Render-only overview of linked accounts |
