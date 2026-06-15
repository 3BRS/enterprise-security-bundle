# Front-end JavaScript for WebAuthn

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle is server-only. Passkey flows need browser-side calls to `navigator.credentials.create()` (registration) and `navigator.credentials.get()` (login), which you supply — with `@simplewebauthn/browser` or vanilla `navigator.credentials.*`. The bundle's `PasskeyWebauthnSerializer` emits JSON the browser API consumes directly, and the options/verify endpoints accept the resulting credential JSON straight back.

The browser flow is:

```
POST  /passkey/login/options       → JSON options
navigator.credentials.get(options) → credential
POST  /passkey/login/verify        → { ok: true, redirect: '/dashboard' }
```

Same shape for registration (`create` instead of `get`, register-options + register-verify endpoints).
