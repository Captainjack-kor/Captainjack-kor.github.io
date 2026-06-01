---
title: "Joplin — Unbounded Title Length DoS (OOM)"
severity: Moderate (5.5)
type: CWE-770 (Allocation of Resources Without Limits or Throttling)
cve: CVE-2025-57798
affected_component: "@joplin/app-desktop"
affected_version: "< 3.3.13"
patched_version: "3.7.0"
reporter: Hyeontaek Lim (Captainjack)
date: 2026-05-15
---

| | |
| --- | --- |
| **Severity** | <span class="sev">Moderate (5.5)</span> |
| **CVSS 3.1** | `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **Type** | CWE-770 — Allocation of Resources Without Limits or Throttling |
| **CVE** | CVE-2025-57798 |
| **Affected** | `@joplin/app-desktop` &lt; 3.3.13 |
| **Patched** | 3.7.0 |
| **Advisory** | [GHSA-6jm8-gr87-q69x](https://github.com/laurent22/joplin/security/advisories/GHSA-6jm8-gr87-q69x) |

## Summary

Joplin's note **title** input performs no maximum-length validation. An attacker can insert an excessively long string into a note title, causing **unbounded memory allocation** that drives the process into an **Out-Of-Memory (OOM)** condition and crashes the application.

Because the malicious title can be **persisted to disk**, the crash also recurs on every subsequent launch — turning a one-shot crash into a **persistent denial of service**.

## Details

### Root Cause — No length limit on title input

The title field accepts arbitrarily large input and processes it without any size cap or throttling (CWE-770). The oversized string is allocated and handled in full, exhausting the heap. There are **two independent attack surfaces**:

#### ▸ Surface 1 — UI (direct input)

Typing or pasting an extremely long string directly into a note/notebook **Title** field triggers immediate memory blow-up and an OOM crash.

#### ▸ Surface 2 — Local Web Service API (port 41184)

Joplin exposes a local web service on **port `41184`**. An attacker holding a valid API token can `POST` a crafted request with an oversized `title` to the `/folders/` endpoint, forcing uncontrolled allocation until the heap limit is exceeded.

```bash
# Representative PoC — Local Web Service (requires a valid API token)
TOKEN="<your_api_token>"
TITLE=$(python3 -c "print('A' * 50_000_000)")   # ~50 MB title string

curl -X POST "http://localhost:41184/folders/?token=${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"title\": \"${TITLE}\"}"
```

## Reproduction

### Steps

```text
1. Launch Joplin                         → local web service starts on :41184
2. Observe baseline memory               → ~755 MB (normal operation)
3. Input an extremely long string into a notebook/note "Title" field
   (or send the API POST above)
4. Memory consumption rapidly climbs     → exceeds ~9300 MB
5. OOM error is raised                    → application terminates
6. Service on :41184 shuts down
7. Relaunch the application
   → if the malicious title was persisted, the app crashes instantly on startup
```

### Memory observation

| State | Memory |
| --- | --- |
| Normal operation | ~755 MB |
| After oversized title | &gt; 9,300 MB → **OOM / crash** |

## Impact

- **Application crash / unexpected termination**, disrupting the user's workflow
- **Data loss** of unsaved work at the moment of the crash
- **System resource exhaustion** degrading overall machine responsiveness

> [!danger] Persistent denial of service
> If the oversized title is **saved**, it is reloaded on the next startup — so the application **crashes immediately every time it launches**, and the user cannot recover access to their notes without manually purging the malicious data.

## Timeline

| Date       | Event                 |
| ---------- | --------------------- |
| 2026-05-15 | Advisory published    |
| —          | Patched in `3.7.0`    |
| —          | CVE-2025-57798 assigned |

## References

- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [GHSA-6jm8-gr87-q69x (Joplin advisory)](https://github.com/laurent22/joplin/security/advisories/GHSA-6jm8-gr87-q69x)
- [CVE-2025-57798](https://nvd.nist.gov/vuln/detail/CVE-2025-57798)
