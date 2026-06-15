# Password Policy

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

Blocks weak passwords at the point of entry — registration, self-service change-password, admin-set passwords — by enforcing configurable length and character-class rules. The requirements are operator-tunable per scope (so admins can be held to a stricter policy than customers) and the validation engine is a framework-agnostic Symfony constraint, so you attach it to whatever property holds the plain password in your app.

**Bundle primitives:**
- `PasswordPolicy\Constraint\PasswordPolicy` — the validation constraint. Attach it to the plain-password property; its `policyGroup` (default `customer`) selects which settings scope the policy is read from.
- `PasswordPolicyValidatorInterface` — the contract for the constraint validator. The bundle ships the contract; you register a concrete validator under the service id `three_brs.validator.password_policy` (the id the constraint's `validatedBy()` returns).
- `PolicyFactory::passwordPolicy(SettingsScope $scope)` — builds the effective `PasswordPolicyInterface` value object (min/max length + the four toggles) from the settings store.
- `PasswordPolicyFilteringValidator` — decorates Symfony's `validator` service and, on a field that already has a `three_brs.password_policy.*` violation, suppresses a duplicate native minimum-length error (your framework's own `*.password.min` message template or `Length::TOO_SHORT_ERROR`) so the user sees one message, not two.

**What it checks:** minimum length, optional maximum length, and independently-toggleable requirements for uppercase, lowercase, numbers and special characters.

## Settings

Read per [`SettingsScope`](../configuration.md#2-settings-store) (`customer` / `admin` / `global`):

| Path | Type |
|---|---|
| `password_policy.min_length` | int |
| `password_policy.max_length` | int, or `null` for no maximum |
| `password_policy.require_uppercase` | bool |
| `password_policy.require_lowercase` | bool |
| `password_policy.require_numbers` | bool |
| `password_policy.require_special_characters` | bool |

Provide initial values through the `three_brs.security_settings.defaults` parameter (consumed by `YamlConfigDefaultsProvider` — see [Configuration §3](../configuration.md#3-feature-flags-compile-time-defaults)). Example:

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            password_policy.min_length: 8
            password_policy.max_length: ~
            password_policy.require_uppercase: false
            password_policy.require_lowercase: false
            password_policy.require_numbers: false
            password_policy.require_special_characters: false
        admin:
            password_policy.min_length: 12
            password_policy.max_length: ~
            password_policy.require_uppercase: true
            password_policy.require_lowercase: true
            password_policy.require_numbers: true
            password_policy.require_special_characters: true
```

## The constraint validator you provide

Register a concrete `PasswordPolicyValidatorInterface` as `three_brs.validator.password_policy`. It maps the constraint's `policyGroup` to a `SettingsScope`, asks `PolicyFactory` for the policy, and raises the constraint's message-template violations:

```php
class PasswordPolicyValidator extends ConstraintValidator implements PasswordPolicyValidatorInterface
{
    public function __construct(protected PolicyFactoryInterface $policyFactory) {}

    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof PasswordPolicy || $value === null || $value === '') {
            return;
        }

        $scope  = $constraint->policyGroup === 'admin' ? SettingsScope::ADMIN : SettingsScope::CUSTOMER;
        $policy = $this->policyFactory->passwordPolicy($scope);
        $length = mb_strlen((string) $value);

        if ($length < $policy->getMinLength()) {
            $this->context->buildViolation($constraint->minLengthMessage)
                ->setParameter('{{ limit }}', (string) $policy->getMinLength())->addViolation();
        }
        // … max length + the four character-class checks, each guarded by the matching policy toggle
    }
}
```

```yaml
services:
    App\Validator\PasswordPolicyValidator:
        arguments: ['@ThreeBRS\EnterpriseSecurityBundle\Settings\PolicyFactoryInterface']
        tags:
            - { name: 'validator.constraint_validator', alias: 'three_brs.validator.password_policy' }
```

> **Suggested ranges** (validate these in your settings UI — the bundle does not clamp them): `min_length` 1–64, `max_length` 1–128, with `max_length` ≥ `min_length`.
