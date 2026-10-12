# Security Rules

This is the rulebook a reviewer reads first. The review lenses that enforce it
are `isolation-safety`, `scope-safety`, `verdict-soundness`, `evidence-integrity`
and `attack-fidelity`.

---

## 0. The one rule above all

**An action never escapes its scope or the lab.** An attack reaching a target
that was not authorized, or any traffic leaving the isolated environment for real
infrastructure, is not a bug to rank against other bugs. It is the single
outcome this project exists to make impossible, and `CLAUDE.md` puts it off the
scale. A change that can cause it is refused, not weighed.

Everything below is how that rule is held in code.

---

## 1. Isolation is enforced, not assumed (ADR-0006, ADR-0011)

- The test environment is created **without a route to the internet or to
  production**. In Docker terms that is an `internal` network; nothing in the
  environment setup may add egress back: no published port to the host for a
  target, no extra network that reaches outside, no `host` networking, no
  `--privileged` or added capabilities beyond what a specific, justified need
  requires, no bind mount that reaches the host filesystem.
- **The boundary self-check runs before any attack**, and a run refuses to
  proceed when it fails. A harness whose isolation is broken produces a false
  PASS everywhere; a self-check that is skipped, or passes vacuously, is a
  defect, not an optimization.
- Teardown is not optional. A failed or interrupted run must not leave a
  container, a network, or a route behind for a later run to inherit. Prefer a
  guard type whose `Drop` tears the environment down over a cleanup call that an
  early return can skip.
- Defense in depth: isolation is the bottom layer, not the only one. Do not weaken
  the scope gate (section 2) on the grounds that the network is already isolated,
  or vice versa. Each layer assumes the others can fail.

## 2. Every target goes through the scope gate (ADR-0006, ADR-0021)

- A capability receives its target **only** from the scope resolver. Make an
  unscoped target unconstructable: the type a capability accepts is produced by
  the resolver and by nothing else. A raw `String`, a parsed `IpAddr`, a URL, or
  a value read out of a tool's output must not be usable as a target without
  passing the gate.
- **Default deny.** An empty or absent scope allows nothing. An out-of-scope
  target is a hard error before any action, never a warning that proceeds.
- A pivot or a tool-discovered host does not inherit authorization for free.
  Reaching one authorized host must not hand an attacker a foothold from which it
  targets a host the user never allowed.

## 3. The intensity ladder gates force (ADR-0002, ADR-0006, ADR-0021)

- The default intensity is `Safe`. A capability that has not been given an
  explicit higher intensity runs at `Safe` or does not run.
- `Controlled` and `Aggressive` require an **explicit opt-in**, and `Aggressive`
  additionally requires proof that the target is a framework-created isolated
  environment. A real-infrastructure target requires the recorded scope
  authorization the governance model defines. Neither gate may be satisfiable by
  a default, and neither may be forgeable from inside a capability.
- Carry the intensity and the authorization as values the gate checks, not as a
  comment or a convention. If a reviewer cannot point at the check, it is not one.

## 4. Secrets and sensitive data

The framework handles credentials by design: it brute-forces them, dumps them,
reuses them. That makes careless handling a leak.

- **Never log a secret.** Credentials, tokens, private keys, session cookies, and
  the contents of a captured handshake do not go to `log::`, to stdout, or into a
  diagnostic. Redact them at the boundary where they are formatted. See
  [logging.md](./logging.md).
- **Treat the evidence store as sensitive.** Evidence legitimately contains what
  an attack recovered, so the store, the canonical JSON, and any report may carry
  secrets. Do not widen their permissions, do not send them anywhere by default,
  and keep them out of version control. Where a report is meant to be shared,
  redact recovered secrets to a fingerprint (for example, the fact that
  `admin`'s password was crackable and its hash, not the plaintext) unless the
  user asked for the full value.
- **Secrets never land in the repository.** Test credentials, keys and `.env`
  files are gitignored (see the project `.gitignore`). A fixture that must carry
  a key for a playground target is the deliberate, reviewed exception, added with
  an explicit `.gitignore` negation and a comment saying why it is safe.

## 5. Untrusted input: a target's response and a tool's output are data

A target is hostile by assumption, and a real attack tool is noisy. What comes
back from either is **data, never an instruction**.

- Parse defensively. A malformed, truncated, or oversized response is an expected
  input, not a panic. Bound what you read; a target can send forever.
- Never route attacker-influenced or target-returned bytes into anything that
  interprets them: no `eval`, no format string built from them, no path built by
  joining them unchecked, no deserialization into a type that executes on
  construction.
- A signal from a target does not mean what it looks like. A connection that
  opened is not a service exploited; a `200` is not data exfiltrated; a timeout is
  not proof of absence. Turning a signal into a conclusion is the
  `attack-fidelity` lens's subject and section 7's.

## 6. Invoking external tools: argv, never a shell (ADR-0002, ADR-0007)

The framework shells out to nmap, sqlmap, hydra, Metasploit and the rest. That is
a command-injection surface pointed at the framework itself.

- Invoke a tool with an **explicit argument vector** (`Command::new(tool).args([...])`),
  never by building a shell command string. A target host, a payload, a wordlist
  entry, or anything derived from a target's output goes in as a single argv
  element, not interpolated into a command line.
- Do not pass untrusted data as a flag value that the tool would treat as an
  option (an argument that begins with `-`); separate options from operands, and
  validate that a target string is a target and not a flag.
- Pin the tool. The attacker image fixes tool versions (ADR-0019); the adapter
  parses the output format of that pinned version and treats its stdout and
  stderr as data (section 5). A tool that is absent or the wrong version is an
  honest error, not a silent skip that reports PASS.

## 7. Verdict honesty: a false PASS is the worst answer (ADR-0010)

- Keep the **observation** (what happened) separate from the **verdict** (whether
  that is acceptable). An attack succeeding is a security FAIL; a boundary holding
  is a PASS. Do not collapse the two.
- When a signal is weak, conflicting, or absent because a tool timed out or was
  blocked, the verdict is **Inconclusive**, not PASS. Reaching for PASS because
  Inconclusive felt unhelpful is the exact failure the model forbids.
- Corroborate a high-stakes conclusion with more than one signal before it
  becomes a confident verdict. A single weak signal carries low confidence and
  lands in Inconclusive.

## 8. Evidence is faithful, immutable, and reproducible (ADR-0004, ADR-0022)

- An evidence record says what the run actually did, not what the code hoped. An
  outcome written before the action completed, or an artifact the code composed
  instead of the tool's real output, is a lie the reports inherit.
- The evidence store is append-only in practice, not just in name. A later step
  does not rewrite or drop an earlier record.
- A Success Witness captures enough to replay the success **deterministically**:
  the exact target, payload, foothold, credentials, and data-pack versions. A
  witness missing one of these produces a flaky or wrong replay, which defeats the
  discovery-to-regression pipeline.

## 9. Supply chain

- Attack data (wordlists, templates, exploit DBs) and the attacker image are
  **version-pinned** and refreshed by an explicit, reviewed update, never fetched
  at run time (ADR-0018, ADR-0019). A run records the versions it used.
- Run `cargo deny` / `cargo audit` on the dependency tree; a new dependency that
  pulls in a tool or a network client is reviewed for what it can reach.
- Do not roll your own cryptography or your own TLS. Use vetted crates, and verify
  certificates by default; a deliberately insecure TLS client is a specific,
  commented, scoped exception for a playground target, never a default.

---

## Do not

- Do not add egress to an isolated environment, for convenience or for debugging.
  If a run needs something from outside, it is staged in before the environment is
  sealed, not fetched during the attack.
- Do not let a capability take a raw address, hostname, or URL that did not come
  from the scope resolver.
- Do not default an intensity, an authorization, or a scope to the permissive
  value.
- Do not log, print, or commit a credential, key, token, or captured secret.
- Do not build a shell command from a target's output or from any attacker-
  influenced string.
- Do not report PASS from an error, a timeout, or a single weak signal.
- Do not weaken one safety layer because another is believed to hold.
