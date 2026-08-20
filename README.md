# tuf-ci

A TUF repository that lives in a git repository, signed on YubiKeys and administered
through pull requests. A pure-Rust rewrite of
[tuf-on-ci](https://github.com/theupdateframework/tuf-on-ci).

Metadata changes happen on `sign/*` branches. CI works out who still has to sign, writes
that into the pull request, and publishes a check run so the merge button reflects it.
Signers run `tuf-sign`, which reads the same state and puts a signature on it.

```
crates/
  tuf-repo/      the signing-event state machine, over the `tuf` crate's metadata
  tuf-yubikey/   signing with PIV slot 9c
  tuf-sign/      the tool a signer runs
  tuf-ci/        the tool GitHub Actions runs
actions/
  signing-event/ the composite action a TUF repository uses
template/        a TUF repository, ready to be copied
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
  .signing-event.json          invitations and pending configuration, during an event
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
at publish time, by concatenation — the payload's bytes are authored once and frozen, since
any reformat would invalidate every signature already collected.

The metadata itself is the [`tuf`](https://github.com/theupdateframework/rust-tuf) crate's
model, read and written through POUF-2. This project adds one object at the root of each
document for the things TUF has no opinion about:

```jsonc
"x-tuf-ci": {
  "signers": { "bd828d85…": "@arlosi" },              // who holds each offline key
  "online":  { "6d1392ab…": "gcpkms:projects/…" },    // where CI reaches each online key
  "periods": { "root": { "expiry-days": 365, "signing-days": 60 } }
}
```

One block, at the top level, never nested inside a key or a role — that is the only place
unrecognised fields survive a round trip, so anything written deeper would be silently
dropped the first time a tool rewrote the document. Keeping it inside the payload also
keeps it signed: how long a role's word is good for is part of what the delegating role's
signers attest to.

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

### As a repository

A TUF repository is its own repository, separate from this one. This repository holds the
tool and the action; that one holds `metadata/`, `targets/`, and the workflow below. The
GitHub App, its secrets and the branch protection all belong to *that* repository — nothing
here needs them.

Set it up in this order. The workflow has to reach the base branch **before** the first
signing event, because a `push` event runs the workflow as it exists in the pushed commit,
not the one on the base branch — so a `sign/*` branch cut from a base branch without the
workflow will push successfully and then do nothing at all.

1. Copy [`template/`](template) into the new repository. It carries the workflow, a
   `.gitattributes` that keeps signature-covered bytes from being mangled, an empty
   `targets/`, and a README with the same steps for whoever runs it.
2. Repoint the `uses:` in `.github/workflows/signing-event.yml` at the `tuf-ci` commit you
   want to run, pinned by SHA.
3. Create the GitHub App, **install it on the new repository**, and add
   `TUF_CI_APP_CLIENT_ID` and `TUF_CI_APP_PRIVATE_KEY`.
4. Push all of that to `main`.
5. Only now run `tuf-sign init sign/init`

Require the `tuf-ci/signatures` check in branch protection on `main` so a signing event
cannot be merged until it has reached its thresholds.

### The GitHub App

Create one in the organisation that owns the repository, with these **repository
permissions**, then install it on the TUF repository only:

| Permission | Level | Why |
|---|---|---|
| Contents | Read and write | commit rebuilt targets metadata to the event branch |
| Pull requests | Read and write | open and update the signing event pull request |
| Checks | Read and write | publish the merge gate |
| Metadata | Read-only | mandatory, selected for you |

It needs no webhook. Store the App's **Client ID** (`Iv23li…`, on the App's settings page
— not its numeric App ID, which the token action has deprecated) as the
`TUF_CI_APP_CLIENT_ID` variable, and the generated private key as the
`TUF_CI_APP_PRIVATE_KEY` secret.

**Installing the App is a separate step from creating it.** An App that exists but is not
installed on the repository authenticates fine and then fails with
`Not Found — /repos/{owner}/{repo}/installation`, which reads like a missing repository
rather than a missing installation.

An App rather than `GITHUB_TOKEN` because opening a pull request with `GITHUB_TOKEN`
requires *Allow GitHub Actions to create and approve pull requests*, which many
organisations disable and which cannot be re-enabled per repository. An App rather than a
personal access token because the check-runs API rejects PATs outright — checks can only
be created by an App — so a PAT would leave the repository with no merge gate.

Passing `app-slug` attributes metadata commits to the App's own bot user. Without it they
are authored by `github-actions[bot]`, which is cosmetic but misleading.

Note that pushes made with an App token **do** trigger workflows, unlike `GITHUB_TOKEN`.
Committing rebuilt targets metadata therefore starts a second run of this workflow. It is
bounded at two and idempotent: the second run finds the metadata already in step with the
artifacts and re-renders the same report.

<details>
<summary>Using GITHUB_TOKEN instead</summary>

Workable if your organisation permits Actions to create pull requests, and if you do not
mind losing the check run:

```yaml
jobs:
  signing-event:
    runs-on: ubuntu-latest
    permissions:
      contents: write        # commit rebuilt targets metadata
      pull-requests: write   # open and update the signing event pull request
      checks: write          # publish the merge gate
    steps:
      - uses: rf-signing-experiment/tuf-ci/actions/signing-event@<commit-sha>
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

`GITHUB_TOKEN` can create check runs, so the merge gate does work here. What it cannot do
is open the pull request when the organisation setting is off; set
`create-pull-request: false` and open it by hand in that case.

</details>

Adding an artifact is an ordinary commit:

```console
$ git switch -c sign/add-serde origin/main
$ mkdir -p targets/crates && cp serde-1.0.0.crate targets/crates/
$ git add targets && git commit -m 'Add serde 1.0.0' && git push -u origin HEAD
```

CI turns that into a targets metadata change, and the pull request says who has to sign it.

## Publishing

`tuf-ci publish` turns the pair of files each role is stored as into what a client fetches:
one DSSE envelope per role, addressed by version, and every artifact addressed by its hash.

```console
$ tuf-ci publish --out dist
+ targets/db45b4f2….serde-1.0.0.crate
+ metadata/2.targets.json
+ metadata/2.snapshot.json
+ metadata/timestamp.json
4 of 11 files written (18422 bytes) to dist
```

```
dist/
  metadata/1.root.json          every root that has ever been signed, so a client that
  metadata/2.root.json            has been away can walk forward to the current one
  metadata/root.json            the current root again, for a client with nowhere to start
  metadata/2.targets.json
  metadata/2.crates.json
  metadata/2.snapshot.json
  metadata/timestamp.json
  targets/db45b4f2….serde-1.0.0.crate
```

It signs nothing and dates nothing. Every byte written is either a document already signed
in git or an artifact those documents describe, so the output is a pure function of the
commit — which is what makes it checkable. An auditor holding no keys runs

```console
$ tuf-ci publish --rev v3 --out /tmp/audit --manifest -
```

and compares the manifest against what is live. `--rev` reads the commit straight out of
git, so there is nothing to check out and nothing local to trust.

Before writing anything, the whole repository is replayed through the `tuf` crate's client
verification: the root chain from its oldest version forward, then timestamp, snapshot,
targets and each delegated role, each against the one that vouches for it. Artifacts are
checked against the signed descriptions as they are read. A repository a client would
reject does not get published.

Publishing needs `snapshot` and `timestamp`, which are the online key's work and not yet
implemented; until then, `publish` says so and stops.

### Uploading it

Every published name but two — `metadata/root.json` and `metadata/timestamp.json` — pins
its own contents, by version number for metadata and by hash for artifacts. So a
republish is cheap by construction: ask the destination what it already has, send the
rest, delete nothing. `tuf-ci publish` does exactly that against a directory, skipping
files already there with the right bytes.

Files go out in dependency order — artifacts, then the metadata describing them, then
`snapshot`, and `timestamp` last — so the live `timestamp.json` never names something that
has not been uploaded yet. An upload that dies halfway leaves the previous repository
working and some unreferenced files behind.

That is the whole design for an object store, and `tuf_repo::publish::Sink` is the seam:
one `ListObjectsV2` to learn what the bucket holds, a `PUT` per missing file in the order
the plan gives them, no delete pass, and the two mutable names always rewritten. Old
versions stay: a `4.snapshot.json` nobody points at any more costs a few kilobytes and is
the difference between a client mid-update carrying on and a client failing.

## How roles work

`root` delegates to `root`, `targets`, `snapshot` and `timestamp`. The top-level `targets`
role delegates to any number of named roles, and a delegated role may not delegate further:
which role owns an artifact is decided by its path, not by a tree walk.

- `targets/file` belongs to the `targets` role — only files sitting directly in `targets/`.
- `targets/<role>/…` belongs to `<role>`, up to four directory levels deep.

A role's signers, threshold and validity periods all live in the role that delegates to it,
so one document says everything about a delegation. Key ids are `sha256` of the DER
`SubjectPublicKeyInfo`, which means recording who owns a key never renames it.

Metadata on a signing-event branch is always *valid* TUF metadata — it just has fewer
signatures than it needs. A configuration that cannot be written validly yet, such as
raising a threshold to two before the second signer has a key, waits in
`.signing-event.json` and lands the moment the last invitation is accepted. So a branch
never holds metadata that a client, or this tool, would refuse to parse.

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
| Metadata model | its own | the `tuf` crate's, with one extension object per document |

## Not implemented yet

The repository can be administered and published, but nothing yet produces the online
roles a publish needs, or uploads the result. Still to come:

- **online signing** — snapshot and timestamp signed with a KMS key when an event merges;
- **scheduled expiry events** — the cron job that opens `sign/<role>-vN` when a role enters
  its signing period;
- **uploading** — an S3 `Sink`, and the workflow that runs it on a merge to `main`.

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
