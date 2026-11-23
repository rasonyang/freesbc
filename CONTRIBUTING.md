# Contributing to FreeSBC

Thanks for helping. These rules keep review time proportional to the change.
A pull request that breaks one is closed without review; reopen it once it
complies.

## Before you start

- **Work from an issue.** Every pull request implements one existing issue.
  For something with no issue, open the issue first and wait for a maintainer
  to say it is wanted.
- **Check the scope rule.** FreeSBC does only what is needed to make one switch
  on a private LAN safely reachable from the public internet; anything the
  switch already does well stays on the switch. The full rule is in
  [docs/edge.md](docs/edge.md#scope-rule).
- **Do not implement an undecided issue.** An issue labelled `design first` or
  `deferred`, or whose text says a decision is still open, is not ready for
  code. Discuss the design in the issue; an implementation is accepted only
  after a maintainer records the decision there and removes the label.

## Pull requests

- **At most 3 open pull requests per contributor.** Open the next one after one
  of yours is merged or closed. Drafts count.
- **One pull request, one issue.** No unrelated fixes, refactors or reformatting
  alongside. If you find a second problem, open a second issue.
- **Do not auto-close the issue.** Write `Refs #123`, not `Fixes`, `Closes` or
  `Resolves`. A maintainer closes the issue after checking its "Done when"
  list.
- **Say what you did not do.** If part of the issue is left out, or a check
  could not be run, state it at the top of the description.
- **No attribution text** in commits, descriptions or files: no "Generated
  with" line and no `Co-Authored-By` trailer for a tool. You are the author and
  answer for every line, however it was written.

## "Verified" means command and output

A claim that something was run, passes or was verified must come with the exact
command and its output, pasted into the pull request description. This covers
tests, `freesbc check`, a Docker rig, `promtool`, and any "Verified with" line
or date in a README.

- No output, no claim. Write "not run" instead; that is acceptable and far
  better than a guess.
- Record a date, version or commit as verified only if the run was on a tree
  that contains your change.
- A statement about how the code behaves, in docs or in the description, cites
  the symbol and file that proves it, never a line number.

## Checks to run

CI runs these; run them before opening the pull request and include the output
of the ones your change touches.

```sh
gofmt -l .
go mod tidy -diff
go vet ./...
go build -o freesbc ./cmd/freesbc && ./freesbc check -c freesbc.example.yaml
go test -race ./...
go test ./internal/doccheck -run '^TestDocCitations$'   # any change to README.md or docs/
```

Many edge tests are timing-based over real loopback sockets. Re-run a failing
test once on its own (`-run '^TestName$' -count=1`) before reporting it.

Write code, comments and docs in English.
