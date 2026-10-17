# Attack techniques

A catalog of attack techniques, one file each, written so a reader meeting a
technique for the first time can learn what it is and how it works. It is the
reference redstep is built from, not a record of what redstep has built: a
capability is implemented by working from the technique file, and a code comment
links back here instead of restating the attack in prose that drifts.

Kept as a catalog, it also shows what is missing. A documented technique with no
capability yet, or a known technique with no file at all, is a gap in coverage made
visible, and closing those gaps is how the native checks grow.

These files are reference, not intent and not decisions. What is wanted lives in
`../roadmap/`; the settled cross-cutting reasoning lives in `../adr/`; a technique
file teaches a real attack, links to both, and says how redstep exercises it, or
will when no capability exists yet.

## Writing one

Copy [`template.md`](template.md) to `docs/attacks/<slug>.md` and fill it in. The
template's own comments say what each section is for.

- **One file per technique; a directory only to hold sub-techniques.** There are no
  genre subfolders (no `web/` or `network/`): the genre is the `targets` tag, not the
  path, so a technique is never re-filed across genres and its path never moves for
  that reason. This is
  [ADR-0016](../adr/0016-tag-attacks-with-attack-and-owasp-optional-but-first-class.md):
  the taxonomy is tag-driven, and a coverage view is generated from the tags. The one
  case a technique becomes a directory is when it maps to an ATT&CK technique that has
  sub-techniques worth teaching on their own (see "Techniques with sub-techniques"
  below); the directory is then the signal that the technique is divided.
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
- **Name the `capability` when one exists, else `none`.** This is the coverage
  signal: a file with `capability: none` is a technique the catalog teaches but
  redstep does not yet exercise, which is exactly the gap the catalog exists to make
  visible. A code comment may link to such a file; keep "How redstep exercises it"
  honest that it is not built yet.

## Techniques with sub-techniques

Most techniques are one flat file. When a technique maps to an ATT&CK technique that
has sub-techniques worth teaching individually, make it a directory instead, so the
split is visible from the tree and a reader sees at once that the technique divides:

```
docs/attacks/brute-force/
  README.md               the umbrella: Summary, Mechanism and References for the
                          general technique, and a list linking its sub-techniques.
                          It carries the parent ATT&CK id (e.g. T1110) and no
                          capability of its own.
  password-spraying.md    one file per sub-technique, the full template, each with
  credential-stuffing.md  its own sub-technique ATT&CK id (T1110.003, .004), its
  ...                     own targets, and its own capability or none.
```

The genre index links the umbrella, one row per recognisable technique, and the
umbrella links its sub-techniques. The path, `brute-force/credential-stuffing.md`, is
the contract a code comment depends on exactly as a flat slug is, so splitting a
technique into a directory, or collapsing one back into a file, is as deliberate as a
rename.

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
file.

Do not list a file before it exists: an entry for a missing file is a dead link,
which `.claude/scripts/docs-links.sh` fails. The genres with no file yet await their
first.

### Web

- [SQL Injection](sql-injection.md)
- [Cross-Site Scripting](xss.md)
- [OS Command Injection](command-injection.md)
- [XML External Entity Injection](xxe.md)
- [Server-Side Template Injection](ssti.md)
- [NoSQL Injection](nosql-injection.md)
- [Insecure Deserialization](insecure-deserialization.md)
- [Insecure Direct Object Reference](idor.md)
- [Path Traversal](path-traversal.md)
- [Server-Side Request Forgery](ssrf.md)
- [Cross-Site Request Forgery](csrf.md)
- [CORS Misconfiguration](cors-misconfiguration.md)
- [Clickjacking](clickjacking.md)
- [Open Redirect](open-redirect.md)
- [Privilege Escalation](privilege-escalation.md)
- [Brute Force](brute-force/README.md)
- [JWT Attacks](jwt-attacks.md)
- [OAuth Vulnerabilities](oauth-vulnerabilities.md)
- [HTTP Request Smuggling](http-request-smuggling.md)
- [HTTP Host Header Attacks](http-host-header-attacks.md)
- [Web Cache Poisoning](web-cache-poisoning.md)
- [Mass Assignment](mass-assignment.md)
- [Business Logic Vulnerabilities](business-logic-vulnerabilities.md)
- [File Upload Vulnerabilities](file-upload-vulnerabilities.md)
- [Race Conditions](race-conditions.md)
- [Information Disclosure](information-disclosure.md)
- [Prototype Pollution](prototype-pollution.md)

### API

- [NoSQL Injection](nosql-injection.md)
- [Insecure Deserialization](insecure-deserialization.md)
- [CORS Misconfiguration](cors-misconfiguration.md)
- [Privilege Escalation](privilege-escalation.md)
- [Brute Force](brute-force/README.md)
- [JWT Attacks](jwt-attacks.md)
- [OAuth Vulnerabilities](oauth-vulnerabilities.md)
- [Mass Assignment](mass-assignment.md)
- [Unrestricted Resource Consumption](unrestricted-resource-consumption.md)
- [Business Logic Vulnerabilities](business-logic-vulnerabilities.md)
- [GraphQL API Vulnerabilities](graphql-api-vulnerabilities.md)
- [Race Conditions](race-conditions.md)
- [Information Disclosure](information-disclosure.md)

### Network

- [Adversary-in-the-Middle](adversary-in-the-middle/README.md)
- [Network Sniffing](network-sniffing.md)
- [Network Service Discovery](network-service-discovery.md)
- [Exploitation of Remote Services](exploitation-of-remote-services.md)
- [DNS Spoofing and Cache Poisoning](dns-spoofing.md)
- [VLAN Hopping](vlan-hopping.md)

### Container

### Cloud

- [Server-Side Request Forgery](ssrf.md)
- [Cloud Instance Metadata Abuse](cloud-instance-metadata-abuse.md)
- [Public Cloud Storage Exposure](public-cloud-storage-exposure.md)
- [Cloud IAM Privilege Escalation](cloud-iam-privilege-escalation.md)
- [Valid Cloud Accounts](valid-cloud-accounts.md)
- [Cloud Service and Infrastructure Discovery](cloud-service-discovery.md)

### Identity

- [Brute Force](brute-force/README.md)
- [JWT Attacks](jwt-attacks.md)
- [OAuth Vulnerabilities](oauth-vulnerabilities.md)
- [Adversary-in-the-Middle](adversary-in-the-middle/README.md)
- [Cloud IAM Privilege Escalation](cloud-iam-privilege-escalation.md)
- [Valid Cloud Accounts](valid-cloud-accounts.md)

## Backlog (not yet written)

This is the coverage gap made visible: known techniques still to catalogue, by genre. A
name moves up into the genre index above, as a link, when its file is written.

The Web, API, Network, and Cloud genres are complete to their mainstream sets: Web and
API from OWASP Top 10 (2021), the OWASP API Security Top 10 (2023), and the PortSwigger
Web Security Academy (pure categories that are not a single technique, security
misconfiguration, improper inventory management, unsafe consumption of APIs, were
deliberately left out); Network and Cloud from the ATT&CK Enterprise and Cloud matrices
(with the techniques that need a radio, a physical switch, or a real cloud provider kept
as `capability: none` and marked out of the software-defined lab's scope). The next
frontier is the genres still uncatalogued:

- **Container:** image and runtime escapes, from the ATT&CK Containers matrix.
- **Identity:** the credential-access techniques beyond the brute-force,
  name-resolution-poisoning, and cloud-account families already listed.

Enumerate each genre from its authoritative taxonomy, as the earlier genres were, before
writing its files.
