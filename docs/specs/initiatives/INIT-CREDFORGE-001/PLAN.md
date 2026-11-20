# PLAN: credforge

**Initiative:** INIT-CREDFORGE-001

## Order

1. **Core first** (RMI-CREDFORGE-001, -002). `Compare` and `Record` are pure
   and carry every rule, so they are written and tested against fixtures
   before any connector exists.
2. **Targets** (RMI-CREDFORGE-003), since `Check` derives its scopes from it.
3. **Connectors** (RMI-CREDFORGE-004, -005), each behind its interface and
   tested against fakes.
4. **Command line** (RMI-CREDFORGE-006), then a check against a real
   registry before the first release.
5. **Release v0.1.0** and make the repository public: README, MkDocs site,
   CHANGELOG, CI, and a clean publication scan. The repository stays private
   until Phase 1 works end to end; it is not published with specs alone.
6. Phases 2 to 4 follow, in order, each released on its own.

## Adoption

A host tool that already builds a credential registry in Go mounts
`cli.New` beside `credspec`'s commands, binds its stores in a targets file,
and replaces any per-store comparison of its own with `credforge check`.

## Risks

| Risk | Mitigation |
|---|---|
| A connector reads a value by mistake | Only listing endpoints are called; tests assert the value endpoints are never hit |
| `stale` and `changed` misfire when events are recorded late | The grace window, a flag, defaulting to 24 hours |
| Registry store accounts are free text | Bindings match accounts exactly or by pattern; unmatched stores are `unobserved`, never `missing` |
| Organization and environment secrets satisfy references in Phase 1 only partly | Organization secrets count when the registry stores them at the owner; the rest arrives in Phase 2 |
| GitHub rate limits on large fleets | One listing per repository, paged; workflow files fetched once per run |

## Definition of done (Phase 1)

- `go test ./...` and `golangci-lint run` pass; coverage reported.
- `credforge check` run against a real registry with GitHub and SSM
  bindings reports the drift it contains, and `--record` writes events that
  `credspec validate` accepts.
- README, docs site, CHANGELOG and release notes for v0.1.0.
