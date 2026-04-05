# Blue/Green Username Rotation of [Standard User](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts#use-case-for-creating-gmsa-account-for-non-domain-joined-container-hosts) username

## What is Blue/Green Rotation?

Blue/green rotation is a credential update strategy borrowed from
blue/green deployments. When the username in AWS Secrets Manager is
changed — whether manually by a user or by an automated rotation policy —
the existing Kerberos tickets on disk are still keyed to the **old** (blue)
username. The service needs to match those old tickets and recreate them
with the **new** (green) username and password. The "blue" and "green"
labels simply distinguish the current-on-disk identity from the newly
desired identity during the transition. Note that when the username is
rotated, the password is also rotated as part of the new account.

## Problem Statement

When customers rotate gMSA credentials in AWS Secrets Manager, the
`RenewNonDomainJoinedKerberosLease` RPC needs to know both the **old** and
**new** usernames so it can:

1. **Match** existing Kerberos tickets (keyed by the old username).
2. **Recreate** those tickets with the new username and password.

The obvious alternative — having credentials-fetcher read the username
directly from Secrets Manager — requires the EC2 **instance role** to have
`secretsmanager:GetSecretValue` permission. In many ECS deployments only the
**task execution role** has that permission, making the direct-read approach
unusable
([aws/credentials-fetcher#218 (comment)](https://github.com/aws/credentials-fetcher/issues/218#issuecomment-4180459269)).

## Short-Term Solution: Colon-Separated Username Format

Active Directory forbids `:` in usernames, so the format is unambiguous.
The caller passes both usernames in the existing `username` field of the
`RenewNonDomainJoinedKerberosLeaseRequest`:

```
oldUser:newUser
```

- `oldUser` (blue) — used to match existing tickets on disk.
- `newUser` (green) — used to create replacement tickets with the new
  credentials.

When no `:` is present the request is treated as a normal (non-rotation)
renewal.

### Behaviour

| Input | Match by | Create with | Metadata updated? |
|-------|----------|-------------|-------------------|
| `alice` | `alice` | `alice` | No (normal renewal) |
| `alice:bob` | `alice` | `bob` | Yes — `DomainlessUser` rewritten to `bob` |
| `alice:alice` | `alice` | `alice` | No (same username, treated as normal renewal) |

On rotation the service:

1. Finds all tickets whose `DomainlessUser` (or Secrets Manager–extracted
   username) matches the old name.
2. Updates `DomainlessUser` to the new name in memory.
3. Persists the updated metadata JSON to disk (hard failure if write fails).
4. Recreates the Kerberos tickets with the new username/password via
   `CreateKerberosTickets`.

### Validation

Each side of the `:` is validated independently — the raw `old:new` string
is never passed to AD account-name validation (which would reject the `:`).

## Long-Term Solution

The colon-separated format is a pragmatic short-term fix that avoids a
protobuf API change. The proper long-term fix is to extend the gRPC API
with `lease_id` and `distinguished_name` fields:

```protobuf
message RenewNonDomainJoinedKerberosLeaseRequest {
    string username           = 1;
    string password           = 2;
    string domain             = 3;
    string lease_id           = 4;   // target a specific lease directly
    string distinguished_name = 5;   // supply DN instead of resolving it
}
```

With `lease_id` the service can locate the exact tickets to renew without
relying on username matching, which eliminates the need for the
`oldUser:newUser` convention entirely. Supplying `distinguished_name`
removes the dependency on ECS config / Secrets Manager / LDAP for DN
resolution during renewal.

Until then, the `oldUser:newUser` convention is documented here and in the
`ParseBlueGreenUsername` function in
`internal/utils/grpc_utils/grpc_utils.go`.
