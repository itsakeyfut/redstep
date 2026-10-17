# Attack techniques

One file per attack technique, each a reference the code links to from its
comments. A capability or a check that implements a technique points a reader here
for what the attack is and what a verdict about it means, rather than carrying a
second copy of that prose in a doc comment that drifts.

These files are reference, not intent and not decisions. What is wanted lives in
`../roadmap/`; the settled cross-cutting reasoning lives in `../adr/`; a technique
file describes a real attack and how redstep exercises it, and links to both.

## Writing one

Copy [`template.md`](template.md) to `docs/attacks/<slug>.md` and fill it in. The
template's own comments say what each section is for.

- **One technique, one file, flat.** No `web/` or `network/` subfolders. The
  classification is the tags inside the file, not the directory, so a technique is
  never re-filed and its path never moves (see below on why that matters). This is
  [ADR-0016](../adr/0016-tag-attacks-with-attack-and-owasp-optional-but-first-class.md):
  the taxonomy is tag-driven, and a coverage view is generated from the tags.
- **Name by the common name, kebab-case:** `ssrf.md`, `sql-injection.md`,
  `idor.md`, `path-traversal.md`. The file name is the `slug`.
- **Tag it, ATT&CK first, OWASP for the app layer, CWE where it sharpens the
  mapping.** All optional and all first-class; `[unmapped]` is a legitimate value,
  so a technique with no standard id still gets a file (ADR-0016).
- **Set `targets`, the attacker-target genre, as a list.** This is how the catalog
  is organised by what an attacker can aim at, and it is a tag, not a folder: the
  file stays flat so its path never moves, and a technique that spans genres
  carries all of them (SSRF is `[web, cloud]`, a web input that pivots to the cloud
  metadata service). The genres are the sections of the index below; keep to that
  set and add one only as deliberately as you would have added a folder. The set:
  `web`, `api`, `network`, `container`, `cloud`, `identity`.
- **Set `status` honestly:** `implemented`, `partial`, or `planned`. A code comment
  may link to a `planned` file; the field is what stops that link promising a
  capability that does not exist yet.

## Linking, and why the slug is frozen

Code comments reference a file by its repository-relative path, for example
`docs/attacks/ssrf.md`. Within `docs/`, `.claude/scripts/docs-links.sh` checks that
every relative link still resolves, so keep the ADR links in a technique file
correct. Nothing checks the **code to docs** direction: a renamed slug breaks every
comment that pointed at the old path and no script will catch it. So the slug and
the section headings are a published contract once a comment links them. Rename one
only as deliberately as a public function.

## Index

Grouped by target genre, the `targets` field. A technique is listed under each
genre it carries, so a cross-genre one (SSRF under both Web and Cloud) appears more
than once; that is the by-genre view the catalog is organised around. Add a file to
every genre in its `targets` as it is written: one row per technique, a link to its
file followed by its status.

Every section is empty until a file exists: an entry for a file that is not there
yet would be a dead link, which `.claude/scripts/docs-links.sh` fails. The
implemented native checks (SSRF, SQL injection, IDOR, path traversal) are the
natural first files, all under Web (SSRF also under Cloud).

### Web

### API

### Network

### Container

### Cloud

### Identity
