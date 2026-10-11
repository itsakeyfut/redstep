# Design and API Conventions

redstep starts as a single crate and splits into a workspace as the milestones
land (Decision M onward). These rules are about **boundaries and invariants**,
which hold whether a boundary is a module today or a crate later. When the split
happens, a layer below becomes a crate below, and the dependency direction here
becomes the crate graph.

---

## 1. The role tiers (Decision G)

Everything that touches a target is one of three roles, and the code keeps them
distinct because they carry different safety obligations:

- **Capability** — an active action, executed as a step: a native primitive or a
  tool adapter (nmap, sqlmap, ...). It passes the scope gate and the intensity
  ladder, and it emits evidence. This is where force lives.
- **Scanner** — a bulk finder (Trivy, Nuclei, ...) that produces findings from a
  target without driving an attack path.
- **Interop** — an importer of a tool that runs on its own (ZAP, Burp,
  BloodHound). redstep does **not** execute it, so it is outside the scope gate;
  it only normalizes a result that already exists.

Do not blur these. In particular, an Interop importer must not be made to launch
the tool it imports, because that would put an unexecuted-by-us tool inside the
guarantees that only hold for things redstep itself runs (security.md section 1-3).

## 2. Layering and dependency direction

The layers, lowest first. Dependencies point **downward** only; no cycles.

```
evidence / verdict / scope / intensity   (the model: pure, no I/O)
        -> capability / adapter           (executes against a target)
        -> environment / network          (builds and tears down the lab)
        -> runner / scenario / reporting   (drives tests, projects evidence)
        -> cli
```

- The **model layer is pure**: the evidence record, the verdict and its oracle,
  the scope and intensity types carry no I/O and no Docker. They are the part
  that must be trivially testable and never able to reach a network. Keep them
  free of `tokio`, `bollard`, and process spawning.
- Safety types (scope-resolved target, intensity, isolation proof) are defined in
  the model layer and **consumed** by the capability layer, so that force cannot
  be applied without a value the model produced. This is the type-level half of
  security.md sections 2 and 3.

## 3. Evidence is the one source of truth (Decision D, V)

- The evidence record is the single source of truth. The terminal report, the
  canonical JSON, the attack graph and the success witness are **projections** of
  it, computed from it, never a second answer that can disagree. A projection that
  derives its own verdict is the drift Decision E exists to prevent.
- Define the evidence type and the verdict type **once**, in the model layer, and
  re-export upward. Never define a second copy in the reporting layer.

## 4. Type placement

- Define a type in the **lowest layer that needs it** and re-export upward. Never
  define the same type twice.
- A type that decides or gates anything safety-relevant (a target, an intensity,
  a verdict, a scope) belongs in the pure model layer, so the gate is enforced by
  the type system rather than by discipline in each caller.

## 5. Encapsulation and `#[non_exhaustive]`

- Public enums that will gain variants over time are `#[non_exhaustive]`: the
  verdict (`Pass` / `Fail` / `Inconclusive` / `Error`), intensity, capability
  kinds, finding categories. This keeps adding a variant non-breaking and steers
  callers toward a wildcard arm.
- A verdict or an outcome match, however, is **total on purpose**: handle every
  variant explicitly rather than with a `_` arm, so that adding one is a compile
  error (`E0004`) that forces every decision site to answer for it. The
  `#[non_exhaustive]` convenience is for downstream crates; inside the crate that
  owns the verdict, exhaustiveness is the guard (CLAUDE.md, verdict-soundness).

## 6. Builder pattern

- Use a consuming builder when a type takes **3 or more optional parameters**:
  an environment definition, a scenario, a capability with options. Required
  parameters go on `new()`.
- Validation is collected in `.build()`, which returns `Result`. Setters do not
  validate. For anything safety-relevant, `.build()` is also where the scope and
  intensity are resolved, so an unvalidated or unscoped object cannot exist.

## 7. The plugin boundary is a contract (Decision G)

- A Capability adapter, a Scanner and an Interop importer each implement a stable
  trait, so a new tool is a new implementation rather than a change to the core.
  Keep the trait narrow: it is what every adapter must honor, including emitting
  evidence and reporting intensity.
- Adapters are static (compiled in) for now; a dynamic plugin mechanism is a
  later decision. Do not add one speculatively.
