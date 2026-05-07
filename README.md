# freenet-git

Git repositories hosted directly on [Freenet](https://freenet.org).
Push, fetch, and clone through the Freenet network using normal Git
commands, without GitHub, GitLab, federation, or a server you operate.
A repository is a Freenet contract; Git sees it through a standard
remote helper.

## Live demos

Hosted on Freenet and clonable today:

```sh
# freenet-core HEAD source snapshot (no full history)
git clone freenet::3GEERif5ihbf/freenet-core

# freenet-stdlib full git history (177 commits)
git clone freenet::96rknpy1GYhZ/freenet-stdlib
```

Requires `cargo install freenet-git` and a running local Freenet node.
See "Quick start" below.

## What this is

Git is already decentralized: every clone is a complete repository,
and any two clones can synchronize directly. What Git usually lacks
is decentralized *hosting* and *discovery*. GitHub, GitLab, and
Forgejo provide that layer by centralizing it on servers.

`freenet-git` moves the hosting layer onto Freenet. Repository state
lives in Freenet contracts; Git interacts with those contracts
through a standard remote helper. The long-term goal is **a
decentralized software forge**: repos first, then pull requests,
issues, CI attestations, releases, and names.

## Quick start

### 1. Install

You need a Rust toolchain. If you don't have one, install via
[rustup.rs](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then:

```sh
cargo install freenet-git
```

This installs both `freenet-git` (the companion CLI) and
`git-remote-freenet` (the Git remote helper). Make sure
`~/.cargo/bin` is on your `PATH`.

### 2. Run a local Freenet node

You need a Freenet node running locally to talk to. See the
[Freenet getting-started guide](https://docs.freenet.org/). The
WebSocket API endpoint defaults to
`ws://127.0.0.1:7509/v1/contract/command`.

### 3. Clone a live repo

```sh
git clone freenet::96rknpy1GYhZ/freenet-stdlib
```

No identity, no setup. Just `git clone` against a real
Freenet-hosted repository.

### 4. Publish your own repo

```sh
freenet-git init-identity --name "Your Name" --email you@example.com
cd ~/code/my-project
freenet-git create --name my-project --description "A thing"
# -> URL: freenet:RtTzy58hMxAB/my-project

git remote add freenet freenet::RtTzy58hMxAB/my-project

# See "Passphrase handling" below for the env-var bit.
export FREENET_GIT_PASSPHRASE='your-passphrase'
git push freenet main
```

### Passphrase handling

`git push` and `git fetch` go through `git-remote-freenet`, which
runs as a child process of git. Git owns stdin and stdout for the
remote-helper protocol, so the helper can't prompt you for a
passphrase interactively. You have two options.

**Encrypted bundle (default).** Set `FREENET_GIT_PASSPHRASE` before
pushing or fetching:

```sh
export FREENET_GIT_PASSPHRASE='your-passphrase'
git push freenet main
```

Avoid putting the passphrase in shell history or long-lived
environment files. A future release will add OS-keychain integration.

**Unencrypted bundle.** Pass `--no-passphrase` when creating the
identity (or when re-encrypting via `export-identity` /
`import-identity`):

```sh
freenet-git init-identity --no-passphrase \
    --name "CI Bot" --email ci@example.com
git push freenet main      # no env var needed
```

The bundle file then holds the signing authority directly — no
encryption layer. Use this when the file already lives in an
authenticated store (CI secrets, an OS keychain, an encrypted
volume); putting a passphrase on top there is redundant. This is
the recommended path for CI workflows that mirror repositories
into Freenet.

## Sending changes to a maintainer

Today freenet-git works the way Linux kernel development worked
before centralized forges: each contributor publishes their own
freenet-hosted clone, and maintainers pull from those clones to
review and merge. There is no shared "canonical repo with everyone
pushing to it" yet (that's Phase 1.1).

A concrete walkthrough. Alice has a fix she wants Bob to consider
for `freenet-core`:

**On Alice's machine:**

```sh
# one-time setup
cargo install freenet-git
freenet-git init-identity --name "Alice" --email alice@example.com

# Alice already has a clone of freenet-core somewhere
cd ~/code/freenet-core
git checkout -b fix-thing
# ... commits ...

# publish her fork as a freenet-hosted repo
freenet-git create --name freenet-core-alice
# -> URL: freenet:Aa12bc34De56/freenet-core-alice

git remote add freenet freenet::Aa12bc34De56/freenet-core-alice
export FREENET_GIT_PASSPHRASE='whatever'
git push freenet fix-thing
```

She then tells Bob her URL through some other channel (Matrix,
email, mailing list, IRC). There is no inbox of incoming proposals
on Freenet itself yet, so the announce-your-fork step is still
out-of-band.

**On Bob's machine:**

```sh
cd ~/code/freenet-core
git remote add alice freenet::Aa12bc34De56/freenet-core-alice
git fetch alice                            # streams from Freenet
git log alice/fix-thing --oneline -5       # review
git checkout -b alice-fix alice/fix-thing
cargo test
# if happy:
git checkout main && git merge alice-fix
```

Mechanically the round trip works end-to-end on the network today.
What's missing is the social layer.

### Where this is heading

The same pattern with the missing pieces filled in:

- **Phase 1.1, multi-writer ACL.** For projects that prefer the
  GitHub-style "everyone pushes to one canonical repo" workflow,
  the repo owner publishes a signed contributor list. Both modes
  will coexist; pick whichever fits the project's culture.
- **Phase 2, proposal contracts.** Alice's `git push` of a feature
  branch optionally publishes a signed "PR" document (commit range,
  description, base ref) to a proposals contract Bob's repo
  subscribes to. Bob's local UI sees incoming PRs without anyone
  having to send a Matrix message. Comments and reviews are signed
  follow-up entries on the same proposal. Cross-repo references
  ("Alice's fix-thing on top of upstream's main@abc1234") become
  first-class.
- **Phase 3, signed CI attestations.** Anyone can run a runner;
  results are signed and posted to a job-queue contract. Viewers
  verify "this commit's tests passed" against whatever trust model
  the project picked (whitelisted runners, N-of-M reproducible
  build agreement, TEE attestation).
- **Phase 4+, issues, releases, discovery.** Issues as per-repo
  append-only signed timelines. Releases as signed tag refs plus
  artifact contracts. Discovery is a search engine over published
  repos plus a reputation signal, not a first-come-first-served
  name registry. You search for "freenet-core", see candidates
  ranked by reputation, and pick the one that's actually upstream
  rather than racing someone to grab a global name.

Until those phases land, the `git remote add` / `git fetch` /
out-of-band-tell-the-maintainer loop above is the supported flow.
It is enough for the substrate to be useful; the forge layers on
top.

## Keeping a published repo alive

Freenet is a communication medium, not a storage medium. Peers
keep contracts in an LRU cache, so anything that nobody has touched
recently is the first thing dropped to make room for hotter content.
For a freenet-git repo this shows up as:

```
error: fetch ChunkedPack ...
Caused by: get exhausted all peers after 4 attempts
```

The fix is to refresh the network's hot copy. Anyone with a node
that still has the contract data cached (typically the original
publisher) can run:

```sh
freenet-git rescue freenet:<prefix>/<label>
```

This re-PUTs every bundle and chunk the repo references, which
re-broadcasts each to whichever peers subscribe to that contract's
location and bumps it back to the top of their LRU cache.

For repos you publish and want to keep reachable, run rescue as a
cron job (e.g. once a day or a few times a week) from a node that
holds the data. The demo URLs above are kept alive by the
`rescue-demos` GitHub Actions workflow in this repo
(`.github/workflows/rescue-demos.yml`); content freshness for the
`freenet-core` and `freenet-stdlib` mirrors is driven from those
upstream repos' workflows that call
`freenet/freenet-git/.github/workflows/mirror-repo.yml`.

Re-pushing unchanged source is a no-op end-to-end: snapshot mode
produces deterministic orphan SHAs, so daily safety-net cron runs
that find no upstream change neither rebuild the pack nor write
the contract. Schedule mirror crons aggressively without worrying
about contract churn -- they only do work when the source
actually moved.

A future release will add `freenet-git rescue --from <git-dir>`
so any clone-holder can rescue from their working tree even if
the local node's cache has also forgotten.

## How URLs work

A freenet-git URL looks like:

```text
freenet:RtTzy58hMxAB/my-project
        ^~~~~~~~~~~~ ^~~~~~~~~~
        prefix       label (optional)
```

For `git remote add` and `git clone`, use the **double-colon** form:

```text
freenet::RtTzy58hMxAB/my-project
```

The double colon is required by Git's
[remote-helpers protocol](https://git-scm.com/docs/gitremote-helpers)
to disambiguate from SCP-style URLs.

### Prefix

The prefix is the first 12 base58 characters of the repo owner's
ed25519 public key (~70 bits). It's the only part that participates
in identity, signatures, and network routing. The full Freenet
contract key is computed locally as
`BLAKE3(BLAKE3(repo-contract.wasm) || serialize({prefix}))`.

Anyone with a current `freenet-git` install resolves the same
contract key from the same prefix. The URL stays stable across
contract WASM upgrades; only the underlying contract key changes,
which the on-host helper handles transparently.

### Label

The label is a human-readable name following the prefix after a `/`.
It's purely cosmetic:

- Two URLs that differ only in their label resolve to the **same**
  repo.
- Git uses the label as the default clone-into directory name, so
  `git clone freenet::RtTzy58hMxAB/my-project` produces a
  `my-project/` directory.
- The label is never sent to the network and never signed against.

## Identity model

Today, only the repo owner can push to a given Freenet repo. Other
developers publish their own Freenet-hosted clones and maintainers
pull from them. This is the same workflow that built the Linux
kernel before centralized forges became dominant.

Phase 1.1 adds opt-in multi-writer ACL for projects that prefer the
GitHub-style "everyone pushes to one canonical repo" model. Both
modes will coexist.

Each repo has its own ed25519 keypair, so compromising one repo's
key does not compromise your cross-repo identity:

- `freenet-git init-identity` creates a default identity (used for
  cross-repo signing in Phase 2: PR comments and reviews).
- `freenet-git create` generates a fresh per-repo keypair and stores
  it in your bundle's `repos` registry. The URL prefix is derived
  from this per-repo public key.
- Bundles are optionally passphrase-encrypted with `scrypt` +
  XChaCha20-Poly1305; pass `--no-passphrase` to skip encryption when
  the file already lives in an authenticated secret store. Move
  them between machines via `freenet-git export-identity` and
  `freenet-git import-identity`.

### Wire-format stability

V1 bundles will continue to open in all future versions. CI keeps
checked-in v1 fixtures at `crates/identity/tests/fixtures/`; any
change that would break existing on-disk bundles trips the
`wire_format` tests, forcing a deliberate decision to either
preserve compatibility or ship a legacy-aware migration. Analogous
to `crates/freenet-git/legacy_contracts.toml` on the contract
side, but enforced via test rather than runtime fallback.

## Status

Experimental. Phase 1 of the design tracked in
[freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).

Working today:

- create a Freenet-hosted Git repository
- push commits (single pack and multi-chunk)
- fetch and clone through Git's remote-helper protocol
- clone live demo repos from the public Freenet network
- `freenet-git rescue <url>` to re-PUT a repo's bundles when chunks
  evict from the wider network (cures `exhausted all peers` errors)

Not yet supported:

- **Multi-writer ACL.** Today only the repo owner can push directly.
  This is closer to Git's original Linus-kernel model: every
  contributor publishes their own Freenet-hosted clone, maintainers
  pull from them. ACL (Phase 1.1) is for people who prefer the
  GitHub-style "everyone pushes to one canonical repo" workflow.
- **Pull requests** as proposal contracts with signed comments and
  reviews (Phase 2).
- **Issues** as per-repo append-only contracts with signed status
  changes and labels (Phase 4+).
- **CI / GitHub Actions equivalent.** The hard part isn't running
  the jobs (anyone can run their own runner). The forge-shaped
  problem is *coordinating* runner queues, posting signed results,
  and giving viewers a way to verify "this commit's tests passed."
  freenet-git will provide the coordination contracts (job queue,
  result attestations); the runners themselves are out-of-process
  workers users opt into running. Runner trust models, ranging from
  N-of-M reproducible-build agreement to TEE attestation to simple
  whitelisted runners, are sketched in
  [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985).
- **Releases / package registry, discovery via search and
  reputation** (Phase 4+). Discovery is not a first-come-first-served
  namespace; it's a search engine over published repos plus a
  reputation signal so people can tell which `freenet-core` is
  the one they want.
## Roadmap

The goal is a decentralized software forge, built incrementally:

- **Phase 1.0 (current):** single-writer push/fetch/clone (the
  Linus-kernel model).
- **Phase 1.1:** opt-in multi-writer ACL for projects that want a
  GitHub-style canonical repo with shared write access.
- **Phase 2:** pull requests as proposal contracts; signed comments
  and reviews; cross-repo references (your fork to maintainer's
  upstream).
- **Phase 3:** CI coordination. Job-queue contracts, signed result
  attestations. Runners are out-of-process workers that users opt
  into running; trust model can range from a simple
  maintainer-whitelist to N-of-M reproducible-build agreement to
  TEE attestation.
- **Phase 4+:** issues (per-repo append-only signed timelines),
  releases (signed tag refs + artifact contracts), discovery via
  search and reputation rather than a first-come-first-served name
  registry, per-user identity contracts that link to PGP/SSH/GitHub
  identities for continuity.

See [freenet-core#3985](https://github.com/freenet/freenet-core/issues/3985)
for the design and rationale.

## Repository layout

```
crates/
  encoding/         length-prefixed signed payloads + canonical CBOR.
                    Wire format both contracts and binaries pin to.
  types/            RepoState, deltas, validate_state, update_state,
                    CRDT merge, ChunkedPack manifest. Pure Rust,
                    unit-tested without WASM.
  identity/         passphrase-encrypted ed25519 keypair bundle.
  repo-contract/    WASM contract: mutable repo state (refs + bundle index).
  pack-contract/    WASM contract: immutable packfile bytes.
  freenet-git/      both binaries (`freenet-git` CLI + `git-remote-freenet`
                    helper) and the bundled contract WASMs.
docs/
  0001-large-repos.md   ChunkedPack design (incl. Codex review).
```

## License

LGPL-3.0-only. See `LICENSE`.
