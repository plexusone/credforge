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
connection. It holds no secrets: a GitHub binding names the environment
variable with the token, and an AWS binding names a profile and region.

```json
{
  "formatVersion": "1",
  "bindings": [
    { "store": "github-actions", "account": "example-org/*", "github": { "tokenEnv": "GITHUB_TOKEN" } },
    { "store": "aws-ssm", "account": "hosting", "aws": { "profile": "hosting", "region": "us-west-2" } }
  ],
  "scan": { "githubRepositories": ["example-org/web", "example-org/api"] }
}
```

- `account` matches the registry store's account exactly, or as a pattern
  such as `example-org/*`; `*` matches any. The first matching binding wins.
- A store no binding reaches is `unobserved`, never `missing`.
- `scan.githubRepositories` lists repositories to check even when the
  registry stores nothing there, so a workflow that reads an unknown secret
  is found.

`credforge schema targets` prints the file's JSON Schema.

## Check

```bash
export GITHUB_TOKEN=$(gh auth token)
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

## In CI

Run `credforge check` on a schedule with a read-only token; the default
`--fail-on missing,stale,unregistered` fails the job when something would
break.
