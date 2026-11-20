# ROADMAP: credforge

**Initiative:** INIT-CREDFORGE-001

Phases group the work; each phase's status follows from its items.

## Phase 1: Observe and compare (read-only)

Released in v0.1.0.

| ID | Item | Status |
|---|---|---|
| RMI-CREDFORGE-001 | Core model: keys, scopes, observations, references, findings, and `Compare` with every rule | done |
| RMI-CREDFORGE-002 | `Record`: log unrecorded stores as `created` and changed stores as `deployed` | done |
| RMI-CREDFORGE-003 | Targets file: bindings from store type and account to connections, with a generated schema | done |
| RMI-CREDFORGE-004 | GitHub observers: Actions repository secrets and workflow `secrets.NAME` references | done |
| RMI-CREDFORGE-005 | AWS SSM observer: parameter names and last change, one level per directory | done |
| RMI-CREDFORGE-006 | `credforge check` and the embeddable command tree, with `--record`, `--fail-on` and JSON output | done |

## Phase 2: More of the world

| ID | Item | Status |
|---|---|---|
| RMI-CREDFORGE-007 | GitHub organization and environment secrets, with an organization secret's selected repositories | planned |
| RMI-CREDFORGE-008 | Issuer observations: fine-grained tokens granted to an organization, their expiry and repositories, against entitlements | planned |
| RMI-CREDFORGE-009 | A scheduled check in CI, with the report as an artifact | planned |
| RMI-CREDFORGE-016 | `cli.Check`: the check command alone, for a host tool's own command tree | done |
| RMI-CREDFORGE-017 | Review page: a local page over the registry, event log and live check, saving review decisions and events | done |

## Phase 3: Install and rotate

| ID | Item | Status |
|---|---|---|
| RMI-CREDFORGE-010 | Destinations: write GitHub Actions secrets (sealed) and SSM `SecureString` parameters | planned |
| RMI-CREDFORGE-011 | `push`: from a master copy named by an OmniVault URI to every store, recording `deployed` | planned |
| RMI-CREDFORGE-012 | `rotate`: generate self-issued values, write the master copy and every store, record `rotated` | planned |
| RMI-CREDFORGE-013 | Plans: every write listed and confirmed before it applies; `--dry-run` | planned |

## Phase 4: Frameworks

| ID | Item | Status |
|---|---|---|
| RMI-CREDFORGE-014 | App credential manifests: an app declares the credentials it reads, checked against the registry | planned |
| RMI-CREDFORGE-015 | Connection credentials: a connections library reports its stored credentials' metadata as observations | planned |
