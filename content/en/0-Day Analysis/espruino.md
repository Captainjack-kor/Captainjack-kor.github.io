---
title: "Espruino — RegExp Group Stack Buffer Overflow (CWE-787)"
severity: High
type: CWE-787 (Out-of-bounds Write)
affected_component: "Espruino — jswrap_regexp.c"
affected_version: "<= 2.29"
patched_version: TBD
affected_file: src/jswrap_regexp.c
affected_function: matchhere (line 216)
reporter: Hyeontaek Lim (Captainjack)
date: 2026-10-29
---

| | |
| --- | --- |
| **Severity** | <span class="sev">High</span> |
| **Type** | CWE-787 (Out-of-bounds Write) — Stack buffer overflow |
| **CVE** | VulDB pending |
| **Affected** | `Espruino` <= 2.29 |
| **Affected file** | `src/jswrap_regexp.c` → `matchhere()` (line 216–218) |
| **Impact** | DoS (crash) / potential memory corruption |
| **Attack vector** | Crafted JavaScript regex with 10+ capture groups |
| **Discovery** | AFL++ persistent multi-core fuzzing (15h, 7.7M executions) |

## Summary

A **stack buffer overflow** (CWE-787) exists in the `matchhere()` function of Espruino's regular expression engine. The function writes to `info.groupStart[info.groups]` and `info.groupEnd[info.groups]` **before** checking whether `info.groups < MAX_GROUPS`. Since `MAX_GROUPS` is 9 and the arrays are `size_t[9]` (indices 0–8), a regex with exactly 10 or more capturing groups causes an **out-of-bounds write at index 9**, overwriting 8 bytes of adjacent stack memory.

This is a **separate bug** from the previously fixed issue [#1487](https://github.com/espruino/Espruino/issues/1487), which addressed deep parenthesis nesting causing stack exhaustion. This bug requires only 10 parentheses and corrupts memory rather than exhausting the stack.

> [!danger] IoT / Wearable impact
> Espruino runs on resource-constrained IoT devices (Bangle.js smartwatch, Puck.js BLE beacon). A malicious JavaScript payload delivered via BLE or web IDE triggers memory corruption on the device.

## Details

### Root cause — bounds check after write

```c
// src/jswrap_regexp.c:216-218
info->groupStart[info->groups] = inputHead - info->input;  // WRITE (OOB when groups==9)
info->groupEnd[info->groups] = -1;                          // WRITE (OOB)
if (info->groups < MAX_GROUPS) info->groups++;              // CHECK (too late)
```

The correct order should check **before** writing:

```c
// Correct fix:
if (info->groups < MAX_GROUPS) {
    info->groupStart[info->groups] = inputHead - info->input;
    info->groupEnd[info->groups] = -1;
    info->groups++;
}
```

### Difference from #1487

| Issue | Trigger | Root cause | Fix |
| --- | --- | --- | --- |
| #1487 | Thousands of parentheses | Recursion depth exhaustion | `jspCheckStackPosition` |
| **This bug** | Exactly 10 parentheses | Array index OOB write | Bounds check before write |

## Reproduction

### PoC (minimal)

```javascript
"x".match(/((((((((((/);
// 10 opening parentheses → info.groups reaches 9 → groupStart[9] OOB write
```

### ASAN output

```text
==PID==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 8 at 0x... thread T0
    #0 matchhere src/jswrap_regexp.c:216
    #1 match src/jswrap_regexp.c:98
    #2 jswrap_string_match src/jswrap_string.c:295
```

Confirmed on Espruino v2.29 with both standard and ASAN builds.

## Impact

- **Stack memory corruption**: 8-byte OOB write (size_t) overwrites adjacent stack variables
- **Write value**: string index position — attacker-influenced but not fully controlled
- **Crash**: DoS on all platforms
- **IoT devices**: memory corruption on devices without ASLR or stack canaries

## Timeline

| Date | Event |
| --- | --- |
| 2026-10-26 | Espruino audit started |
| 2026-10-29 | Vulnerability discovered via AFL++ fuzzing |
| 2026-10-29 | ASAN reproduction confirmed (v2.29) |
| 2026-11 | VulDB submission |
| TBD | CVE assigned |

## References

- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [Espruino GitHub](https://github.com/espruino/Espruino)
