# Getting Started

## Install

```bash
go install github.com/plexusone/credforge/cmd/credforge@latest
```

## What you need

- A credential registry and its event log in
  [systemspec-credential](https://github.com/plexusone/systemspec-credential)'s
  format. Each credential lists its stores by `type`, `account` and `path`,
  such as `github-actions`, `example-org/web`, `DEPLOY_TOKEN`.
- Read access to the stores: a GitHub token that can read the repositories'
  Actions secrets and contents, and AWS credentials that may call
  `ssm:DescribeParameters`.

## Write a targets file

The targets file binds each store type and account the registry names to a
connection. It holds no secrets: a GitHub binding may name the environment
variable with the token, and an AWS binding names a profile and region.

```json
{
  "formatVersion": "1",
  "bindings": [
    { "store": "github-actions", "account": "example-org/*", "github": {} },
    { "store": "aws-ssm", "account": "hosting", "aws": { "profile": "hosting", "region": "us-west-2" } }
  ],
  "scan": { "githubRepositories": ["example-org/web", "example-org/api"] }
}
```

- A GitHub binding without `tokenEnv` uses `GITHUB_TOKEN`, then `GH_TOKEN`,
  then your GitHub CLI sign-in (`gh auth token`), so signing in with
  `gh auth login` is enough. With `tokenEnv`, only that variable is used.
- `account` matches the registry store's account exactly, or as a pattern
  such as `example-org/*`; `*` matches any. The first matching binding wins.
- A store no binding reaches is `unobserved`, never `missing`.
- A credential that is optional, by tag or by `need`, or needed only while
  another rotates (`need: rotation`), is never `missing`; once a store
  holds it, it is reported.
- `scan.githubRepositories` lists repositories to check even when the
  registry stores nothing there, so a workflow that reads an unknown secret
  is found.

`credforge schema targets` prints the file's JSON Schema.

## Check

```bash
credforge check --registry credentials.json --events events.json --targets targets.json
```

Read the findings from the top: `missing`, `stale` and `unregistered` are
things that break builds and deploys; `changed` and `unrecorded` are gaps in
the log; `unlisted` are names the registry does not know.

## Record

```bash
credforge check --record --fail-on ''
```

Logs each unrecorded store as `created` and each changed one as `deployed`,
at the time the store reports, by `credforge`. The registry is never edited.

## Install a value

When an issuer shows you a new value, such as a GitHub token, install it
into every store the registry lists for it:

```bash
credforge install app/ci/deploy --dry-run   # list the writes
credforge install app/ci/deploy             # confirm, then paste the value
```

It checks the value first (a GitHub token must read each repository its
entitlements name), writes each store, and records `created` or `rotated`
with the expiry, then `verified`. A later `credforge check` shows the
stores as present.

## In CI

Run `credforge check` on a schedule with a read-only token; the default
`--fail-on missing,stale,unregistered` fails the job when something would
break.
