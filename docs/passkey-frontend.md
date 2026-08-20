# Front-end JavaScript for WebAuthn

> Part of the [ThreeBRS Enterprise Security Bundle](../README.md) integration guide.

The bundle is server-only. Passkey flows need browser-side calls to `navigator.credentials.create()` (registration) and `navigator.credentials.get()` (login), which you supply — with `@simplewebauthn/browser` or vanilla `navigator.credentials.*`. The bundle's `PasskeyWebauthnSerializer` emits JSON the browser API consumes directly. The verify endpoints do **not** take that credential back raw, though — they expect it wrapped, with the credential itself as a **string**:

```js
// login verify
body: JSON.stringify({ credential: JSON.stringify(credential) })

// registration verify — same, plus an optional label (trimmed, max 64 chars, defaults to "Passkey")
body: JSON.stringify({ credential: JSON.stringify(credential), label: 'MacBook Touch ID' })
```

Posting the credential object at the top level, or nesting it as an object rather than a string, returns `400 {"error":"Missing credential payload."}` — the same response as a genuinely malformed body, so it is worth getting right before you debug the ceremony itself.

The browser flow is:

```
POST  /passkey/login/options       → JSON options
navigator.credentials.get(options) → credential
POST  /passkey/login/verify        → { ok: true, redirect: '/dashboard' }
```

Same shape for registration (`create` instead of `get`, register-options + register-verify endpoints).
