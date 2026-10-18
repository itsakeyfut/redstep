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
  `web`, `api`, `network`, `container`, `cloud`, `identity`, `ai`.
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

One deliberate exception: a technique that is reference-only and out of the
software-defined lab's scope may fold its sub-techniques into a single flat file,
naming them in the body, rather than spend a directory of files redstep will never
exercise. The identity genre's Active-Directory and host-OS techniques
(`os-credential-dumping`, `kerberos-ticket-attacks`,
`alternate-authentication-material`) do this; an in-scope technique with
sub-techniques still gets a directory, as `brute-force` does.

## Linking, and why the slug is frozen

Code comments reference a file by its repository-relative path, for example
`docs/attacks/ssrf.md`. Within `docs/`, `.claude/scripts/docs-links.sh` checks that
every relative link still resolves, so keep the ADR links in a technique file
correct. Nothing checks the **code to docs** direction: a renamed slug breaks every
comment that pointed at the old path and no script will catch it. So the slug and
the section headings are a published contract once a comment links them. Rename one
only as deliberately as a public function.

## Implementing a technique

The catalog is the backlog for the native checks: a file whose `capability` is `none` is a
technique redstep documents but does not yet exercise. Build checks by choosing from here
rather than inventing a technique ad hoc, preferring the ones with the most real-world
impact. When a check is implemented:

- set that file's `capability` to the capability string the code uses (for example
  `http_ssrf_vantage`), so the index stops showing it as a gap;
- rewrite its "How redstep exercises it" and "What a verdict means" from the planned
  future tense to what the code actually does;
- keep the code's doc comment pointing back at the file, so the link holds both ways.

Until a technique has a file here it is not ready to implement: add it to the catalog
first, enumerated from its authoritative taxonomy, so what is built is always something the
catalog already describes.

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
- [Session Hijacking](session-hijacking.md)
- [File Inclusion (LFI and RFI)](file-inclusion.md)
- [Code Injection](code-injection.md)
- [XPath Injection](xpath-injection.md)
- [LDAP Injection](ldap-injection.md)
- [Server-Side Includes Injection](ssi-injection.md)
- [IMAP/SMTP Injection](smtp-injection.md)
- [HTTP Verb Tampering](http-verb-tampering.md)
- [HTTP Parameter Pollution](http-parameter-pollution.md)
- [Vulnerable and Outdated Components](vulnerable-and-outdated-components.md)
- [Improper LLM Output Handling](improper-output-handling.md)
- [Valid Accounts](valid-accounts.md)

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
- [XPath Injection](xpath-injection.md)
- [LDAP Injection](ldap-injection.md)
- [HTTP Verb Tampering](http-verb-tampering.md)
- [HTTP Parameter Pollution](http-parameter-pollution.md)
- [Vulnerable and Outdated Components](vulnerable-and-outdated-components.md)
- [Valid Accounts](valid-accounts.md)

### Network

- [Adversary-in-the-Middle](adversary-in-the-middle/README.md)
- [Network Sniffing](network-sniffing.md)
- [Network Service Discovery](network-service-discovery.md)
- [Exploitation of Remote Services](exploitation-of-remote-services.md)
- [DNS Spoofing and Cache Poisoning](dns-spoofing.md)
- [VLAN Hopping](vlan-hopping.md)

### Container

- [Container Escape to Host](container-escape-to-host.md)
- [Container Runtime Socket Exposure](container-socket-exposure.md)
- [Container and Resource Discovery](container-and-resource-discovery.md)
- [Credentials in Container Images](credentials-in-container-images.md)

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
- [Credentials in Container Images](credentials-in-container-images.md)
- [Session Hijacking](session-hijacking.md)
- [Use of Alternate Authentication Material](alternate-authentication-material.md)
- [Multi-Factor Authentication Bypass](mfa-bypass.md)
- [OS Credential Dumping](os-credential-dumping.md)
- [Kerberos Ticket Attacks](kerberos-ticket-attacks.md)
- [Valid Accounts](valid-accounts.md)
- [Phishing](phishing.md)

### AI

- [Prompt Injection](prompt-injection.md)
- [Improper LLM Output Handling](improper-output-handling.md)
- [System Prompt Leakage](system-prompt-leakage.md)
- [LLM Sensitive Information Disclosure](llm-sensitive-information-disclosure.md)
- [Excessive Agency](excessive-agency.md)

## Coverage

The mainstream set across all seven genres is now catalogued, audited against its
authoritative taxonomies: Web and API from OWASP Top 10 (2021), the OWASP API Security Top
10 (2023), and the PortSwigger Web Security Academy; Network, Cloud, Container, and
Identity from the ATT&CK Enterprise, Cloud, and Containers matrices and the Credential
Access tactic; AI from the OWASP Top 10 for LLM Applications (2025); all cross-checked
against OWASP WSTG and the CWE Top 25.

The taxonomies above are themselves built from real-world data, but to confirm the catalog
against what actually causes damage rather than only what the frameworks list, it is also
cross-checked against two empirical sources: the CISA Known Exploited Vulnerabilities (KEV)
catalog, the vulnerabilities observed exploited in the wild, and the Verizon Data Breach
Investigations Report (DBIR), what actually causes breaches. KEV's prominent types (OS
command injection, deserialization, path traversal, XSS, code injection, improper
authentication, SSRF, and edge-device RCE) all map to existing files, so it validated the
coverage rather than expanding it. DBIR's leading initial-access vectors did surface two
gaps the earlier scope decision had left out, both access-gaining and so in scope, now
added: credential abuse (its top vector) as [valid accounts](valid-accounts.md), and
[phishing](phishing.md) (its third). DBIR's other major theme, ransomware, is a
post-compromise impact and stays out of scope (below).

What is still deliberately left out, each for a reason: pure categories that
are not a single technique (security misconfiguration, improper inventory management,
unsafe consumption of APIs); native memory-safety weaknesses (out-of-bounds, use-after-free,
integer overflow, from the CWE Top 25) that are reached, not themselves tested, via
[exploitation of remote services](exploitation-of-remote-services.md); and the physical and
client-user initial-access vectors (drive-by, trusted relationship, removable media, Wi-Fi).
Phishing, though social, is now catalogued because it is empirically a top vector, kept
`capability: none` and marked outside the non-interactive lab. Techniques that need a radio,
a physical switch, a real cloud provider, or an Active Directory domain are likewise kept
as `capability: none` and marked out of the software-defined lab's scope.

The backlog is therefore empty within scope, and the coverage gap is now visible the other
way: in the index above, every technique whose `capability` is `none` is one redstep does
not yet exercise, which is the list of checks still to build. New techniques are added as
the field evolves, each enumerated from its authoritative taxonomy before its file is
written.

### Out of current scope: the post-compromise lifecycle

The catalog's scope is techniques by which an attacker gains or escalates access against a
target. The post-compromise attacker lifecycle, lateral movement (beyond
[exploitation of remote services](exploitation-of-remote-services.md)), command and
control, persistence, defense evasion, collection, and exfiltration, from the later ATT&CK
Enterprise tactics, is deliberately not catalogued yet. redstep's model reaches toward it
(the attack graph and a C2 session as a foothold, ADR-0020), so it is the next frontier
for the catalog when that part of the tool is built; enumerate it from the ATT&CK tactics
then, as the access-gaining genres were.
