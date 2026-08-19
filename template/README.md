# A TUF repository

The metadata lives in `metadata/`, the artifacts it vouches for in `targets/`. Changes are
made on `sign/*` branches, reviewed as pull requests, and signed on YubiKeys. CI reports
who still has to sign and publishes a check that gates the merge.

## Setting this repository up

1. **Create the repository from this template**, then delete this section from the README.
2. **Create a GitHub App** in the organisation that owns the repository, with these
   repository permissions:

   | Permission | Level | Why |
   |---|---|---|
   | Contents | Read and write | commit rebuilt targets metadata to the event branch |
   | Pull requests | Read and write | open and update the signing event pull request |
   | Checks | Read and write | publish the merge gate |
   | Metadata | Read-only | mandatory, selected for you |

   It needs no webhook.

3. **Install the App on this repository.** Installing is a separate step from creating; an
   App that exists but is not installed authenticates fine and then fails with
   `Not Found — /repos/{owner}/{repo}/installation`, which reads like a missing repository
   rather than a missing installation.

4. **Add the credentials.** Store the App's **Client ID** (`Iv23li…` from its settings
   page, not the numeric App ID) as the `TUF_CI_APP_CLIENT_ID` variable, and the generated
   private key as the `TUF_CI_APP_PRIVATE_KEY` secret.

5. **Pin the action.** `.github/workflows/signing-event.yml` points at `@main`; change it
   to the `tuf-ci` commit you want to run, by SHA.

6. **Push all of that to the default branch — before creating any signing event.** A push
   event runs the workflow as it exists in the pushed commit, so a `sign/*` branch cut from
   a base branch without the workflow will push successfully and then do nothing at all.

7. **Create the metadata**: `tuf-sign init sign/init`. Whoever runs this becomes the
   repository's first signer, so have your YubiKey to hand.

8. **Require the `tuf-ci/signatures` check** in branch protection on the default branch.
   Without it the report is advisory and nothing stops an unsigned merge.

## Working in it

Adding an artifact is an ordinary commit:

```console
$ git switch -c sign/add-serde origin/main
$ mkdir -p targets/crates && cp serde-1.0.0.crate targets/crates/
$ git add targets && git commit -m 'Add serde 1.0.0' && git push -u origin HEAD
```

CI turns that into a targets metadata change and the pull request says who has to sign it.
Signers run `tuf-sign sign/add-serde`.

Changing who may sign a role, or adding a delegated role, is
`tuf-sign delegate sign/<event> <role>`.

## Rules the metadata lives by

- **Never reformat anything under `metadata/`.** A signature covers the exact bytes of its
  payload file, so a reformat — an editor-on-save, a JSON prettifier, a merge tool
  rewriting line endings — invalidates every signature already collected. `.gitattributes`
  turns off line-ending translation; the rest is discipline.
- **One open signing event per role.** Two events that both propose version N+1 of the same
  role cannot both merge, and rebasing the loser means collecting its signatures again.
- **`snapshot` and `timestamp` are signed automatically** and must not be changed in a
  signing event; a branch that touches them is reported as an error.
