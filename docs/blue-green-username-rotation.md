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

## Manual Integration Test

The following test was performed against credentials-fetcher 2.0-2 on an
AL2023 EC2 instance (non-domain-joined ECS cluster) with an AWS Managed
Microsoft AD (`contoso.com`).

### Prerequisites

- gMSA account `WebApp01` created in AD with group `WebAppAccounts_OU`
- Both `StandardUser01` and `StandardUser02` exist in AD and are members of
  `WebAppAccounts_OU`
- Secret `aws/directoryservice/contoso/standarduser` in Secrets Manager

### Step 1: Create a lease with StandardUser01

```python
response = stub.AddNonDomainJoinedKerberosLease(
    credentialsfetcher_pb2.CreateNonDomainJoinedKerberosLeaseRequest(
        credspec_contents=[credspec_json],
        username="StandardUser01",
        password="<StandardUser01_password>",
        domain="contoso.com"
    )
)
```

**Result:**
```json
{
  "success": true,
  "lease_id": "48bc39b8e422f64cde60",
  "created_kerberos_file_paths": ["/var/credentials-fetcher/krbdir/48bc39b8e422f64cde60/WebApp01"]
}
```

Metadata on disk shows `"domainless_user": "StandardUser01"`.

### Step 2: Update Secrets Manager to blue-green format

```json
{
  "password": "<StandardUser02_password>",
  "domainName": "contoso.com",
  "username": "StandardUser01:StandardUser02"
}
```

### Step 3: Renew with blue-green username

```python
response = stub.RenewNonDomainJoinedKerberosLease(
    credentialsfetcher_pb2.RenewNonDomainJoinedKerberosLeaseRequest(
        username="StandardUser01:StandardUser02",
        password="<StandardUser02_password>",
        domain="contoso.com"
    )
)
```

**Result:**
```json
{
  "success": true,
  "renewed_kerberos_file_paths": ["/var/credentials-fetcher/krbdir/48bc39b8e422f64cde60/WebApp01/krb5cc"]
}
```

### Step 4: Verify metadata rotation

```json
{
  "krb_ticket_info": [
    {
      "credential_arn": "arn:aws:secretsmanager:us-west-2:XXXXXXXXXXXX:secret:aws/directoryservice/contoso/standarduser-XXXXXX",
      "distinguished_name": "CN=WebApp01,OU=MYOU,OU=Users,OU=contoso,DC=contoso,DC=com",
      "domain_name": "contoso.com",
      "domainless_user": "StandardUser02",
      "krb_file_path": "/var/credentials-fetcher/krbdir/48bc39b8e422f64cde60/WebApp01/krb5cc",
      "service_account_name": "WebApp01"
    }
  ]
}
```

`domainless_user` was rewritten from `StandardUser01` → `StandardUser02`,
confirming the blue-green rotation worked end-to-end.


## ECS Renewal Flow

In ECS mode, the ECS agent manages the full lifecycle of Kerberos tickets:

1. **Task start:** ECS agent reads the secret from Secrets Manager and calls
   `AddNonDomainJoinedKerberosLease` with the username and password.
2. **Periodic renewal:** ECS agent re-reads the secret from Secrets Manager
   on each renewal cycle (~hourly) and calls
   `RenewNonDomainJoinedKerberosLease` with the current username and
   password.
3. **Task stop:** ECS agent calls `DeleteKerberosLease` to clean up.

Because the ECS agent re-reads the secret on every renewal, blue-green
rotation works without task restart:

```
Time 0:  Secret = "StandardUser01", password = pw1
         → AddNonDomainJoinedKerberosLease(username="StandardUser01", ...)
         → metadata: domainless_user = "StandardUser01"

Time 1:  Customer rotates secret to "StandardUser01:StandardUser02", password = pw2
         → RenewNonDomainJoinedKerberosLease(username="StandardUser01:StandardUser02", ...)
         → Matches tickets by "StandardUser01", recreates with "StandardUser02"
         → metadata: domainless_user = "StandardUser02"

Time 2+: Secret still "StandardUser01:StandardUser02"
         → RenewNonDomainJoinedKerberosLease(username="StandardUser01:StandardUser02", ...)
         → Matches tickets by "StandardUser02" (active username fallback)
         → Normal kinit renewal (no recreation needed)
```

The ECS agent source (`credentialspec_linux.go`) fetches fresh credentials
from Secrets Manager before each renewal call via
`asm.GetSecretFromASM(domainlessGmsaUserArn, asmClient)`.

## Post-Rotation Renewal (Active Username Fallback)

After a successful blue-green rotation, the secret may remain in
`oldUser:newUser` format indefinitely (customers are not required to
update it back to a single username). The renewal flow handles this:

1. Parse `oldUser:newUser` → `matchUsername=oldUser`,
   `activeUsername=newUser`.
2. Scan metadata for tickets with `domainless_user == oldUser` → none
   found (rotation already applied).
3. **Fallback:** scan for tickets with `domainless_user == activeUsername`
   → found.
4. Since tickets already have the active username, no rotation is needed —
   renew normally via direct kinit.

This fallback is implemented in `RenewNonDomainJoinedKerberosLease` with
the `needsRotation` flag:

```go
needsRotation := false
if isRotation {
    for _, ticketInfo := range matchingTicketInfos {
        if ticketInfo.DomainlessUser == matchUsername {
            needsRotation = true
            break
        }
    }
}
```

### Mixed-State Handling

In rare cases (e.g., partial failure during rotation), some tickets in a
metadata file may have the old username while others already have the new
username. The code handles this by only recreating tickets that still need
rotation:

```go
if needsRotation {
    for _, ticketInfo := range matchingTicketInfos {
        if ticketInfo.DomainlessUser == matchUsername {
            ticketInfo.DomainlessUser = activeUsername
            ticketsToRecreate = append(ticketsToRecreate, ticketInfo)
        } else {
            // Already rotated — renew normally
            krbClient.RenewKerberosTicket(ctx, ticketInfo.KrbFilePath)
        }
    }
}
```

This ensures already-valid tickets are not unnecessarily destroyed and
recreated, and a failure to recreate one ticket does not block renewal of
others.


### Edge Cases

| Scenario | Input | Behaviour |
|----------|-------|-----------|
| Normal renewal (no rotation) | `alice` | Match by `alice`, renew directly |
| First rotation | `alice:bob` | Match by `alice`, recreate with `bob`, update metadata |
| Post-rotation renewal | `alice:bob` (metadata has `bob`) | Match by `bob` (fallback), renew directly |
| Reverse rotation (green→blue) | `bob:alice` (metadata has `bob`) | Match by `bob`, recreate with `alice`, update metadata |
| Post-reverse renewal | `bob:alice` (metadata has `alice`) | Match by `alice` (fallback), renew directly |
| Same username both sides | `alice:alice` | Treated as normal renewal (no rotation) |
| Multiple rotations | `alice:bob` then `bob:charlie` | Each rotation matches old, recreates with new |
| Unrelated username | `charlie:dave` (metadata has `alice`) | No match → renewal fails |

**Green→Blue (reverse rotation):** The system supports rotating back to
the original user. If the secret is changed from `alice:bob` to
`bob:alice`, the next renewal will:

1. Parse `bob:alice` → `matchUsername=bob`, `activeUsername=alice`
2. Find tickets with `domainless_user=bob` (from the previous rotation)
3. Recreate them with `alice` credentials
4. Update metadata to `domainless_user=alice`

Subsequent renewals with `bob:alice` will match by `alice` (active
username fallback) and renew normally. The rotation is fully
bidirectional.
