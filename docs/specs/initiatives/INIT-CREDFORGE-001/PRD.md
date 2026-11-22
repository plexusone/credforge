# PRD: credforge — check and act on a credential registry

**Initiative:** INIT-CREDFORGE-001
**Status:** proposed

## Problem

A team that runs a few hosted apps soon holds dozens of credentials:
deploy-time secrets in a cloud parameter store, CI tokens in GitHub Actions,
OAuth client secrets, API keys for analytics and DNS providers, root keys
kept offline. A registry without values, such as
[systemspec-credential](https://github.com/plexusone/systemspec-credential),
says what should exist, where each value is kept, who uses it and how it
rotates, and an event log says what happened to it.

A registry is only as good as its last edit. Nothing compares it with the
places it describes, so it drifts, and the drift is found when something
breaks:

- A CI token is regenerated at the issuer. One repository's secret is
  updated; another keeps the revoked value, and its builds fail days later.
- A workflow starts reading a secret the registry does not list for that
  repository, and the repository never had it set.
- A token's access is widened at the issuer, or not widened when a new
  private dependency arrives, and the registry's entitlements no longer say
  what the token can do.
- A secret is changed in a store and nobody records it, so the rotation
  calendar is wrong.

Each of these is visible from the stores and issuers themselves, without
reading a single value: a secret's name and when it was last set, a
workflow file's `secrets.NAME` references, a parameter's last-modified time.

## Goal

credforge reads a credential registry and its event log, observes the
stores, issuers and consumers it names, and reports where they disagree. It
records what it observes as events. Later it installs and rotates values,
taking them from a master copy through [OmniVault](https://github.com/plexusone/omnivault)
providers and writing them to every store the registry lists.

## Users

- **An operator** who keeps a registry for a small fleet and wants one
  command that says what is missing, stale or unrecorded before a deploy or
  a release.
- **A host tool**, such as a deployment CLI, that already builds a registry
  in Go and mounts credforge's commands over it.
- **CI**, running the check on a schedule and failing when drift appears.

## Requirements

### Phase 1: observe and compare (read-only)

1. **Never read a value.** Observers list names, dates and metadata only.
   No type has a field for a value. A connector that cannot list without
   reading values is not written.
2. **Compare a registry with stores.** For each active credential and each
   of its stores credforge can observe, report one of:
   - `present`: the store holds it;
   - `missing`: the store does not;
   - `stale`: the store was last set before the credential's latest
     `created` or `rotated` event, so it holds an earlier value;
   - `changed`: the store was set after the latest event, and nothing
     recorded why;
   - `unrecorded`: present, and the log has no event for it at all.
3. **Report what the registry does not know.** Names in an observed scope
   (a repository's Actions secrets, a parameter directory) that no
   credential names are `unlisted`.
4. **Check consumers against stores.** A GitHub workflow that references
   `secrets.NAME` in a repository where the registry stores no `NAME` is
   `unregistered`. This finds the secret a workflow needs before CI does.
5. **Record observations.** With `--record`, an unrecorded present store is
   logged as `created`, and a changed store as `deployed`, at the time the
   store reports, by `credforge`. The registry is never edited.
6. **Connect by binding, not by guessing.** A small targets file binds each
   store `type` and `account` in the registry to how it is reached (an AWS
   profile and region, a GitHub token's environment variable). A store
   without a binding is reported as `unobserved`, not as missing.
7. **First connectors:** GitHub Actions repository secrets, GitHub workflow
   files, and AWS Systems Manager Parameter Store.
8. **A gate.** `credforge check` exits non-zero when any finding is in the
   states chosen with `--fail-on` (default `missing,stale,unregistered`).
9. **Embeddable.** The command line is a Cobra command a host tool mounts
   over a registry it builds itself, as systemspec-credential's is.

### Phase 2: more of the world

10. GitHub organization and environment secrets, with the repositories an
    organization secret is shared with.
11. Issuer observations: the expiry and repository access of fine-grained
    personal access tokens granted to an organization, compared with the
    registry's entitlements and expiry events.
12. Scheduled checks in CI, with a report artifact.

### Phase 3: install and rotate

13. **Install.** Take a value the operator has, such as a token an issuer
    just showed once, read it hidden from the terminal, check it works
    (a GitHub token reads each repository its entitlements name), write it
    to each store the registry lists, and record it with its expiry. One
    command replaces setting each store by hand and recording it after.
14. **Push.** Write a value from a master copy, named by an OmniVault URI
    (`op://…`, `aws-sm://…`, `keyring://…`), to each store the registry
    lists for that credential, then record `deployed` per store.
15. **Rotate.** For credentials the operator generates (random secrets, key
    pairs), make a new value in memory, write it to the master copy and
    every store, and record `rotated`. Issuer-made credentials print the
    issuer step and then push.
16. **Plans first.** Every write runs as a plan that lists each store it
    would change and asks before applying. `--dry-run` only prints it.

### Phase 4: frameworks

17. An app framework can declare the credentials an app reads, so credforge
    checks an app's configuration against the registry.
18. A connections library that stores tenants' credentials can report their
    metadata (names, issuer, last rotation) as observations, never values.

## Non-goals

- Storing values. credforge keeps none; master copies stay in the vaults
  OmniVault reaches.
- Replacing the registry format. systemspec-credential owns the schema, the
  event log, the lifecycle state and the reports.
- Runtime secret access inside apps. That is OmniVault's and VaultGuard's.
- Key management. Encryption key lifecycles are KeyForge's.

## Success measures

- Each drift above is reported by `credforge check` before it breaks a
  build or a deploy.
- A fleet's GitHub and parameter-store credentials are checked in one
  command, with no value leaving its store.
- After Phase 3, rotating a CI token is one issuer step and one command.
