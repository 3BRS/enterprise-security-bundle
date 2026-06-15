# Self-Service Account Deletion (GDPR)

> Feature guide for the [ThreeBRS Enterprise Security Bundle](../../README.md).

User-driven account deletion implementing the GDPR right to erasure, with a configurable grace period and admin-side cancellation. Intentionally **customer-scope only** — admin self-deletion is not exposed (admin lifecycle is an operations responsibility, not GDPR self-service).

**Bundle primitives:**
- `GracePeriodCalculator` (`GracePeriodCalculatorInterface`) — `calculateScheduledFor($now, $gracePeriodDays)`.
- `AbstractDueDeletionsProcessor` (`DueDeletionsProcessorInterface`) — `process(): int` finds due requests via your `CustomerDeletionRequestRepositoryInterface` and, for each, calls `onBeforeAnonymize($request)` (e.g. send the "completed" email while the data is still live), then `anonymize($request)`, then `commit()`. You implement those three hooks.
- `UserAnonymizerInterface` — `anonymize(UserInterface $user)`; your impl scrubs the personal data.
- `CustomerDeletionRequestRecordInterface` / `CustomerDeletionRequestRepositoryInterface` — the persisted request (requestedAt, scheduledFor, cancelledAt, requestedByAdmin). See [Entities & persistence](../entities-and-persistence.md).
- Controllers: `AbstractAccountDeletionRequestController` (customer request), `AbstractAccountDeletionCancelController` (admin cancel), `AccountDeletionsListController` (concrete admin list of pending requests) — see [Controllers](../controllers.md#reference-abstract-controllers-and-their-bind-surface) for their bind surface and registration.

## The flow

1. **Request** (`AbstractAccountDeletionRequestController`) — the customer re-authenticates with their current password (no email round-trip) and acknowledges the consequences. Your subclass creates a request record (`requestedAt = now`, `scheduledFor = GracePeriodCalculator::calculateScheduledFor(now, graceDays)`), disables login immediately, invalidates the session, and (optionally) emails a confirmation.
2. **Cancellation** — customer self-cancellation is intentionally not exposed; only an admin can cancel, via `AbstractAccountDeletionCancelController` (+ the list controller). Cancelling re-enables the account and stamps `cancelledAt` + the acting admin for audit.
3. **Grace expiry** — `AbstractDueDeletionsProcessor::process()` runs on a schedule and anonymizes everything past its `scheduledFor`. Send the "completed" email from `onBeforeAnonymize()` (the email is still live at that point).

## The anonymizer you provide

`UserAnonymizerInterface::anonymize()` is where you scrub the personal data. The spec scope is **name / email / phone / address** — clear those fields and overwrite the email with a non-routable placeholder (e.g. `deleted-{id}@anonymized.invalid`). What you *retain* (order and payment rows, address snapshots on past orders) is your decision: accounting / tax-retention obligations generally take precedence over erasure for that data. If your domain needs stricter erasure, layer a project-level cleanup on top.

## Running the processor

The bundle ships the processor; you provide a thin console command (or scheduler task) that calls `process()`, and run it on a cron. See [Controllers your app must provide §6](../controllers-you-provide.md#6-account-deletion-anonymization-cron).

```cron
0 * * * * php /path/to/app/bin/console app:account-deletion:process-due
```

> **Cron is required.** Without the processor running periodically, requests reach `scheduledFor` but never anonymize — the user stays disabled while their personal data lingers in the DB indefinitely.

## Settings

Read at `SettingsScope::CUSTOMER` only:

| Path | Type |
|---|---|
| `account_deletion.enabled` | bool |
| `account_deletion.grace_period_days` | int |

Example defaults (via the `three_brs.security_settings.defaults` parameter):

```yaml
parameters:
    three_brs.security_settings.defaults:
        customer:
            account_deletion.enabled: false
            account_deletion.grace_period_days: 30
```

> **Suggested range** (validate in your settings UI — the bundle does not clamp it): `grace_period_days` 1–90.
