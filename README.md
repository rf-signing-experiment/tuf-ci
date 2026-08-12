# tuf-ci

A TUF repository that lives in a git repository, signed on YubiKeys and administered
through pull requests. A pure-Rust rewrite of
[tuf-on-ci](https://github.com/theupdateframework/tuf-on-ci).

Metadata changes happen on `sign/*` branches. CI works out who still has to sign, writes
that into the pull request, and publishes a check run so the merge button reflects it.
Signers run `tuf-sign`, which reads the same state and puts a signature on it.

```
crates/
  tuf-repo/      the metadata model and the signing-event state machine
  tuf-yubikey/   signing with PIV slot 9c
  tuf-sign/      the tool a signer runs
  tuf-ci/        the tool GitHub Actions runs
actions/
  signing-event/ the composite action a TUF repository uses
```

## Repository layout

```
metadata/
  root.json                    the payload: readable, reviewable JSON
  root.sig.json                the signatures over root.json's exact bytes
  targets.json
  targets.sig.json
  crates.json                  a delegated role
  crates.sig.json
  root_history/1.root.json     every published root, for clients walking the chain
  .signing-event.json          open invitations, present only during an event
targets/
  top-level.txt                owned by the `targets` role
  crates/serde                 owned by the `crates` role
```

Signatures are [DSSE](https://github.com/secure-systems-lab/dsse): each one covers
`PAE("application/vnd.tuf+json", <the exact bytes of the payload file>)`. Because the
payload appears verbatim in the signed bytes, producer and verifier never have to agree on
a canonical JSON dialect.

Payload and signatures are kept in separate files so that git diffs stay useful: adding a
signature produces a four-line diff and touches nothing else, and a metadata change reads
as JSON rather than as a base64 blob. The two are combined into a published DSSE envelope
at publish time.

## Using it

### As a signer

```console
$ tuf-sign                      # show the events waiting on you, and act on one
$ tuf-sign sign/add-crates      # work on a named event
$ tuf-sign status               # look, change nothing
$ tuf-sign delegate sign/add-crates crates
$ tuf-sign init sign/init       # create a new repository's metadata
```

The first run asks for your GitHub handle and which remotes to use, and saves them to
`.tuf-ci.toml`. That file is added to `.git/info/exclude`, so it stays out of commits.

Everything happens in a temporary git worktree. Whatever you had checked out is left alone,
and you do not need a clean working tree to sign.

Your YubiKey needs an ECDSA P-256 key in PIV slot 9c:

```console
$ ykman piv keys generate --algorithm ECCP256 --touch-policy cached 9c public.pem
```

No PKCS#11 module and no certificate in the slot are required — the public key is read
directly from slot metadata.

### As a repository

```yaml
# .github/workflows/signing-event.yml
name: TUF signing event
on:
  push:
    branches: ['sign/**']

permissions: {}

jobs:
  signing-event:
    runs-on: ubuntu-latest
    permissions:
      contents: write        # commit rebuilt targets metadata
      pull-requests: write   # open and update the signing event pull request
      checks: write          # publish the merge gate
    steps:
      - uses: arlosi/tuf-ci/actions/signing-event@<commit-sha>
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

Require the `tuf-ci/signatures` check in branch protection on `main`, and a signing event
cannot be merged until it has reached its thresholds.

Adding an artifact is an ordinary commit:

```console
$ git switch -c sign/add-serde origin/main
$ mkdir -p targets/crates && cp serde-1.0.0.crate targets/crates/
$ git add targets && git commit -m 'Add serde 1.0.0' && git push -u origin HEAD
```

CI turns that into a targets metadata change, and the pull request says who has to sign it.

## How roles work

`root` delegates to `root`, `targets`, `snapshot` and `timestamp`. The top-level `targets`
role delegates to any number of named roles, and a delegated role may not delegate further:
which role owns an artifact is decided by its path, not by a tree walk.

- `targets/file` belongs to the `targets` role — only files sitting directly in `targets/`.
- `targets/<role>/…` belongs to `<role>`, up to four directory levels deep.

A role's signers, threshold and validity periods all live in the role that delegates to it,
so one document says everything about a delegation. Key ids are `sha256` of the DER
`SubjectPublicKeyInfo`, which means annotating a key — recording who owns it, say — does
not rename it.

`snapshot` and `timestamp` are signed by an automated key and never take part in a signing
event; a branch that changes them is reported as an error.

## Differences from tuf-on-ci

| | tuf-on-ci | here |
|---|---|---|
| Encoding | canonical JSON, signature in the same file | DSSE, payload and signatures in separate files |
| Key ids | `sha256` of the whole JSON key object, so annotating a key renamed it | `sha256` of the key material |
| State machine | one for the signer, a near-duplicate for CI | one, shared |
| Known-good state | clone the repository into a temp directory on every run | read the merge-base commit out of git |
| Signing checkout | checks the event out in place, restores with `git checkout -` | a throwaway worktree |
| Hardware access | PKCS#11 via `libykcs11`, configured by path | PC/SC directly |
| PR reporting | a new comment on every run | the pull request body, updated in place, plus a check run |
| Role periods | on the delegate for offline roles, on the delegator for online ones | on the delegator, always |

## Not implemented yet

The repository can be administered but not yet published. Still to come:

- **online signing** — snapshot and timestamp signed with a KMS key when an event merges;
- **scheduled expiry events** — the cron job that opens `sign/<role>-vN` when a role enters
  its signing period;
- **publish and verify** — building the consistent-snapshot tree for GitHub Pages and
  smoke-testing it with a client.

The metadata format and the `tuf-repo` API are shaped so each of these is an addition
rather than a rework.

## Development

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets -- --deny warnings
```

`tuf-yubikey` needs `libpcsclite` to link (`apt install libpcsclite-dev`). `tuf-ci` does
not depend on it, which is why the released CI binary is a small static musl build.

Tests never touch hardware: `tuf-repo`'s `testing` feature provides a software signer, and
`crates/tuf-ci/tests/e2e.rs` drives real git repositories and the real `tuf-ci` binary with
it.
