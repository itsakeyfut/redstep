# Coverage audit

This is the audit behind the catalog's claim to hold the major attack techniques. It maps
each entry of the authoritative taxonomies to a catalog file, or records why it was left
out. A gap is a source entry with neither, and the point of the matrix is to make a gap
visible instead of assumed.

**Scope.** Techniques by which an attacker gains or escalates access against an
application, API, network, cloud, container, identity, or AI target. The post-compromise
lifecycle (lateral movement, C2, persistence, exfiltration) is deliberately out of scope,
see the README. **Granularity.** One file per recognisable technique; a coarse category or
a fine sub-technique maps to the file(s) at that grain.

**To re-run:** re-read each source below, check every entry still maps to a file or a
recorded exclusion, and add or exclude any new entry. `docs-links.sh` keeps the links here
honest; it cannot tell you a source added an entry, so the sources are listed with their
editions.

## OWASP Top 10 (2021)

| Entry | Catalogued as / excluded |
|---|---|
| A01 Broken Access Control | [idor](idor.md), [path-traversal](path-traversal.md), [privilege-escalation](privilege-escalation.md), [csrf](csrf.md), [open-redirect](open-redirect.md), [http-verb-tampering](http-verb-tampering.md) |
| A02 Cryptographic Failures | Partial: the disclosure case is [information-disclosure](information-disclosure.md). The crypto-configuration weakness (weak TLS, bad storage) is a configuration state, not a single attack technique: excluded. |
| A03 Injection | [sql-injection](sql-injection.md), [xss](xss.md), [command-injection](command-injection.md), [code-injection](code-injection.md), [ssti](ssti.md), [nosql-injection](nosql-injection.md), [xpath-injection](xpath-injection.md), [ldap-injection](ldap-injection.md), [ssi-injection](ssi-injection.md), [smtp-injection](smtp-injection.md) |
| A04 Insecure Design | [business-logic-vulnerabilities](business-logic-vulnerabilities.md) |
| A05 Security Misconfiguration | [xxe](xxe.md) (merged into A05 in 2021), [cors-misconfiguration](cors-misconfiguration.md), [clickjacking](clickjacking.md). The broad "misconfiguration" category is not a single technique: excluded. |
| A06 Vulnerable and Outdated Components | [vulnerable-and-outdated-components](vulnerable-and-outdated-components.md) |
| A07 Identification and Authentication Failures | [brute-force](brute-force/README.md), [jwt-attacks](jwt-attacks.md), [oauth-vulnerabilities](oauth-vulnerabilities.md), [session-hijacking](session-hijacking.md), [mfa-bypass](mfa-bypass.md) |
| A08 Software and Data Integrity Failures | [insecure-deserialization](insecure-deserialization.md) |
| A09 Security Logging and Monitoring Failures | Excluded: a defensive gap, not an attack technique. |
| A10 Server-Side Request Forgery | [ssrf](ssrf.md) |

## OWASP API Security Top 10 (2023)

| Entry | Catalogued as / excluded |
|---|---|
| API1 Broken Object Level Authorization | [idor](idor.md) |
| API2 Broken Authentication | [brute-force](brute-force/README.md), [jwt-attacks](jwt-attacks.md), [oauth-vulnerabilities](oauth-vulnerabilities.md), [mfa-bypass](mfa-bypass.md) |
| API3 Broken Object Property Level Authorization | [mass-assignment](mass-assignment.md) |
| API4 Unrestricted Resource Consumption | [unrestricted-resource-consumption](unrestricted-resource-consumption.md) |
| API5 Broken Function Level Authorization | [privilege-escalation](privilege-escalation.md) |
| API6 Unrestricted Access to Sensitive Business Flows | [business-logic-vulnerabilities](business-logic-vulnerabilities.md) |
| API7 Server Side Request Forgery | [ssrf](ssrf.md) |
| API8 Security Misconfiguration | [cors-misconfiguration](cors-misconfiguration.md); the broad category excluded as above. |
| API9 Improper Inventory Management | Excluded: an API-management gap, not a single attack technique. |
| API10 Unsafe Consumption of APIs | Excluded as a category; the concrete case of a vulnerable upstream is [vulnerable-and-outdated-components](vulnerable-and-outdated-components.md). |

## OWASP Top 10 for LLM Applications (2025)

| Entry | Catalogued as / excluded |
|---|---|
| LLM01 Prompt Injection | [prompt-injection](prompt-injection.md) |
| LLM02 Sensitive Information Disclosure | [llm-sensitive-information-disclosure](llm-sensitive-information-disclosure.md) |
| LLM03 Supply Chain | Excluded: ML supply-chain/governance; the dependency case is [vulnerable-and-outdated-components](vulnerable-and-outdated-components.md). |
| LLM04 Data and Model Poisoning | Excluded: an ML training-pipeline/governance concern, not an access technique against a running target. |
| LLM05 Improper Output Handling | [improper-output-handling](improper-output-handling.md) |
| LLM06 Excessive Agency | [excessive-agency](excessive-agency.md) |
| LLM07 System Prompt Leakage | [system-prompt-leakage](system-prompt-leakage.md) |
| LLM08 Vector and Embedding Weaknesses | Excluded: RAG-infrastructure/governance. |
| LLM09 Misinformation | Excluded: output quality, not an attack technique. |
| LLM10 Unbounded Consumption | Excluded: DoS-adjacent; see [unrestricted-resource-consumption](unrestricted-resource-consumption.md). |

## CWE Top 25 (2024)

| CWE | Catalogued as / excluded |
|---|---|
| CWE-79 XSS | [xss](xss.md) |
| CWE-787 Out-of-bounds Write | Excluded: native memory safety; reached via [exploitation-of-remote-services](exploitation-of-remote-services.md). |
| CWE-89 SQL Injection | [sql-injection](sql-injection.md) |
| CWE-352 CSRF | [csrf](csrf.md) |
| CWE-22 Path Traversal | [path-traversal](path-traversal.md) |
| CWE-125 Out-of-bounds Read | Excluded: native memory safety. |
| CWE-78 OS Command Injection | [command-injection](command-injection.md) |
| CWE-416 Use After Free | Excluded: native memory safety. |
| CWE-862 Missing Authorization | [privilege-escalation](privilege-escalation.md) |
| CWE-434 Unrestricted File Upload | [file-upload-vulnerabilities](file-upload-vulnerabilities.md) |
| CWE-94 Code Injection | [code-injection](code-injection.md) |
| CWE-20 Improper Input Validation | Generic; realised by the injection and input-validation files above. |
| CWE-77 Command Injection | [command-injection](command-injection.md) |
| CWE-287 Improper Authentication | The authentication family: [brute-force](brute-force/README.md), [jwt-attacks](jwt-attacks.md), [oauth-vulnerabilities](oauth-vulnerabilities.md), [mfa-bypass](mfa-bypass.md). |
| CWE-269 Improper Privilege Management | [privilege-escalation](privilege-escalation.md), [cloud-iam-privilege-escalation](cloud-iam-privilege-escalation.md) |
| CWE-502 Deserialization of Untrusted Data | [insecure-deserialization](insecure-deserialization.md) |
| CWE-200 Exposure of Sensitive Information | [information-disclosure](information-disclosure.md) |
| CWE-863 Incorrect Authorization | [privilege-escalation](privilege-escalation.md), [idor](idor.md) |
| CWE-918 SSRF | [ssrf](ssrf.md) |
| CWE-119 Improper Restriction of Memory Buffer | Excluded: native memory safety. |
| CWE-476 NULL Pointer Dereference | Excluded: native memory safety. |
| CWE-798 Use of Hard-coded Credentials | [credentials-in-container-images](credentials-in-container-images.md) |
| CWE-190 Integer Overflow | Excluded: native memory safety. |
| CWE-400 Uncontrolled Resource Consumption | [unrestricted-resource-consumption](unrestricted-resource-consumption.md) |
| CWE-306 Missing Authentication for a Critical Function | Folded into [privilege-escalation](privilege-escalation.md). |

## MITRE ATT&CK (in-scope tactics)

ATT&CK is the primary axis for the network, cloud, container, and identity genres (ADR-0016).
The in-scope tactics are the access-gaining ones; the rest are the post-compromise lifecycle
left out of scope (README).

- **Initial Access (TA0001):** Exploit Public-Facing Application (T1190) is the whole Web and
  API set; Valid Accounts (T1078) is [valid-cloud-accounts](valid-cloud-accounts.md) for the
  cloud case. Phishing, drive-by compromise, trusted relationship, hardware additions,
  removable media, and Wi-Fi are excluded as social, physical, or client-user vectors.
- **Credential Access (TA0006):** [brute-force](brute-force/README.md),
  [os-credential-dumping](os-credential-dumping.md), [kerberos-ticket-attacks](kerberos-ticket-attacks.md),
  [alternate-authentication-material](alternate-authentication-material.md),
  [network-sniffing](network-sniffing.md),
  [adversary-in-the-middle](adversary-in-the-middle/README.md) (name resolution poisoning),
  [mfa-bypass](mfa-bypass.md), [cloud-instance-metadata-abuse](cloud-instance-metadata-abuse.md).
  Forced Authentication (T1187) is folded into name-resolution poisoning.
- **Discovery (TA0007):** [network-service-discovery](network-service-discovery.md),
  [cloud-service-discovery](cloud-service-discovery.md),
  [container-and-resource-discovery](container-and-resource-discovery.md).
- **Privilege Escalation (TA0004):** [privilege-escalation](privilege-escalation.md),
  [cloud-iam-privilege-escalation](cloud-iam-privilege-escalation.md),
  [container-escape-to-host](container-escape-to-host.md).
- **On-path and runtime:** [adversary-in-the-middle](adversary-in-the-middle/README.md),
  [dns-spoofing](dns-spoofing.md), [vlan-hopping](vlan-hopping.md),
  [container-socket-exposure](container-socket-exposure.md),
  [exploitation-of-remote-services](exploitation-of-remote-services.md) (the one Lateral
  Movement technique kept, as the engine of reaching a vulnerable service).

## OWASP WSTG and PortSwigger

Cross-checked against the OWASP Web Security Testing Guide (input-validation section) and the
PortSwigger Web Security Academy topic list. The WSTG cross-check is what surfaced
[file-inclusion](file-inclusion.md), [xpath-injection](xpath-injection.md),
[ldap-injection](ldap-injection.md), [ssi-injection](ssi-injection.md),
[smtp-injection](smtp-injection.md), [http-verb-tampering](http-verb-tampering.md), and
[http-parameter-pollution](http-parameter-pollution.md). WSTG configuration and
cryptography testing map to the excluded misconfiguration and crypto-configuration
categories, not to attack-technique files.
