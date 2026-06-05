# Front-end JavaScript for WebAuthn

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle is server-only. Passkey flows need browser-side calls to `navigator.credentials.create()` (registration) and `navigator.credentials.get()` (login). You can:

1. **Copy the JS** from the [Sylius plugin's `src/Resources/public/js/passkey.js`](https://github.com/3BRS/sylius-enterprise-security-plugin/blob/main/src/Resources/public/js/passkey.js) — it talks to the bundle's options/verify endpoints out of the box.
2. **Write your own** using `@simplewebauthn/browser` or vanilla `navigator.credentials.*`. The bundle's `PasskeyWebauthnSerializer` produces JSON the browser API consumes directly.

The browser flow is:

```
POST  /passkey/login/options       → JSON options
navigator.credentials.get(options) → credential
POST  /passkey/login/verify        → { ok: true, redirect: '/dashboard' }
```

Same shape for registration (`create` instead of `get`, register-options + register-verify endpoints).
