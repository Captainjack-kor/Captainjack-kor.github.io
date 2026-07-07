---
title: "Bento4 — Heap OOB Read in Raw AC-4 TOC Parser (AP4_Ac4Header)"
severity: Moderate
type: CWE-125 (Out-of-bounds Read)
cve: CVE-2026-38232
affected_component: "Bento4 / mp4mux — Ap4Ac4Parser.cpp"
affected_version: "v1.6.0-641"
patched_version: TBD
affected_file: Source/C++/Codecs/Ap4Ac4Parser.cpp
affected_function: AP4_Ac4Header::AP4_Ac4Header (line 130)
reporter: Hyeontaek Lim (Captainjack)
date: 2026-06-05
---

| | |
| --- | --- |
| **Severity** | <span class="sev">Moderate</span> *(self-assessed)* |
| **Type** | CWE-125 (Out-of-bounds Read) |
| **CVE** | CVE-2026-38232 |
| **Affected** | `Bento4` v1.6.0-641 |
| **Affected file** | `Source/C++/Codecs/Ap4Ac4Parser.cpp` → `AP4_Ac4Header::AP4_Ac4Header()` (line 130) |
| **Crash site** | `Source/C++/Core/Ap4Utils.cpp` → `AP4_BitReader::ReadCache()` (line 447) |
| **Impact** | DoS (crash) / potential information disclosure |
| **Attack vector** | Crafted Raw AC-4 (`.ac4`) file processed by `mp4mux` |
| **Reference** | [axiomatic-systems/Bento4#1060](https://github.com/axiomatic-systems/Bento4/issues/1060) |

## Summary

A **heap out-of-bounds read** (CWE-125) exists in the **AC-4 parser** of Bento4 (`v1.6.0-641`). When `mp4mux` ingests a crafted **Raw AC-4 (`.ac4`)** bitstream, the `AP4_Ac4Header` constructor parses the stream's **Table of Contents (TOC)**, which declares the number of presentations (`m_NPresentations`).

The parser **trusts that count without validating it against the remaining bitstream size**. By declaring a **high `m_NPresentations`** while supplying **insufficient payload data**, an attacker forces the bit reader to keep pulling bits **past the end of the heap-allocated buffer** — a 1-byte heap over-read that crashes the process (**DoS**) or, depending on heap layout, may leak **adjacent heap contents** into the parse (**information disclosure**).

> [!danger] Untrusted-media processing pipelines
> Any service that uses Bento4 / `mp4mux` to **transcode or remux untrusted AC-4 audio** (media ingestion backends, upload converters, CI media pipelines) is exposed: a single crafted `.ac4` file reaching the muxer triggers the over-read **with no upper-bound check** along the parse path.

## Details

### Root cause — declared presentation count trusted without a bounds check

The AC-4 TOC carries `m_NPresentations` (the number of presentations encoded in the frame). `AP4_Ac4Header`'s constructor reads this value and then **iterates that many times**, parsing each presentation via `ParsePresentationV1Info()`. Each iteration consumes bits through `AP4_BitReader::ReadBits()` → `AP4_BitReader::ReadCache()`.

The missing validation is simple but critical: **the remaining number of bytes in the bitstream is never compared against the number of presentations the header claims to contain.** When the declared count outruns the actual payload, the bit reader walks off the end of its buffer.

```text
Crafted Raw AC-4 (.ac4): high m_NPresentations, short payload
    ↓
m_NPresentations = N            (large, attacker-controlled)
remaining bitstream             (too small for N presentations — NOT checked)
    ↓
for (i = 0; i < N; i++)  ParsePresentationV1Info()
    ↓
ReadBits() → ReadCache()        → index advances past buffer end → OOB READ
```

`m_NPresentations` is read **straight from the TOC bitstream** — no upper bound is enforced (`Ap4Ac4Parser.cpp`, v1.6.0-641):

```cpp
// Ap4Ac4Parser.cpp — AP4_Ac4Header ctor, TOC parse
m_BSinglePresentation = bits.ReadBit();
if (m_BSinglePresentation == 1) {
    m_NPresentations = 1;
} else {
    m_BMorePresentations = bits.ReadBit();
    if (m_BMorePresentations == 1) {
        m_NPresentations = AP4_Ac4VariableBits(bits, 2) + 2;   // :82 — attacker-controlled
    } else {
        m_NPresentations = 0;
    }
}
```

The constructor then loops `m_NPresentations` times, consuming bits for each presentation **with no check on remaining input**:

```cpp
// Ap4Ac4Parser.cpp:128 — "ac4_presentation_v1_info()"
for (unsigned int pres_idx = 0; pres_idx < m_NPresentations; pres_idx++) {
    AP4_Dac4Atom::Ac4Dsi::PresentationV1& presentation = m_PresentationV1[pres_idx];
    presentation.ParsePresentationV1Info(bits, /* … */);   // :130 — keeps consuming bits
}
```

### Call chain (from the ASAN trace)

```text
main()                                              Mp4Mux.cpp:2368
  └─ AddAc4Track()                                  Mp4Mux.cpp:868
       └─ AP4_Ac4Parser::FindFrame()               Ap4Ac4Parser.cpp:405
            └─ AP4_Ac4Header::AP4_Ac4Header()       Ap4Ac4Parser.cpp:130   ← parses TOC
                 └─ ...::ParsePresentationV1Info()  Ap4Dac4Atom.cpp:1329
                      └─ AP4_BitReader::ReadBits()  Ap4Utils.cpp:467
                           └─ AP4_BitReader::ReadCache()  Ap4Utils.cpp:447  ← OOB READ (size 1)
```

### Why the over-read happens

`ParsePresentationV1Info()` consumes bits through `AP4_BitReader::ReadBits()`, which refills its word cache from `ReadCache()`. `ReadCache()` performs **no bounds check** — it simply dereferences the next bytes of the buffer (`Ap4Utils.cpp`):

```cpp
AP4_BitReader::BitsWord
AP4_BitReader::ReadCache() const
{
    const AP4_UI08* out_ptr = m_Buffer.GetData() + m_Position;
    return (((AP4_BitReader::BitsWord) out_ptr[0]) << 24) |   // :447 — OOB read (size 1)
           (((AP4_BitReader::BitsWord) out_ptr[1]) << 16) |
           (((AP4_BitReader::BitsWord) out_ptr[2]) <<  8) |
           (((AP4_BitReader::BitsWord) out_ptr[3])      );
}
```

Once the loop has consumed all real payload, `m_Position` advances past the end of `m_Buffer`; the next `out_ptr[0]` dereference reads **one byte beyond the heap allocation** — exactly the **"READ of size 1"** AddressSanitizer reports. Because the loop trip count comes **directly from the attacker-controlled `m_NPresentations`**, the over-read is **deterministic and reliably triggerable**.

## Reproduction

### Build with AddressSanitizer

Build Bento4 `v1.6.0-641` with ASan enabled so the over-read is caught at the moment it occurs (CMake — adjust flags for your toolchain):

```bash
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address -g -O0" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O0" ..
cmake --build .
```

### Trigger

Feed the crafted Raw AC-4 file to `mp4mux` as an AC-4 track:

```bash
# crafted .ac4: high m_NPresentations, truncated payload
mp4mux --track ac4:crash.ac4 out.mp4
```

> [!note] PoC withheld
> The crafted-`.ac4` generator and exact field values are withheld here; the trigger concept (declare a large `m_NPresentations`, truncate the presentation payload) is described above, and the public report is tracked in [Bento4#1060](https://github.com/axiomatic-systems/Bento4/issues/1060).

### ASAN evidence

AddressSanitizer reports a **heap-buffer-overflow READ of size 1** originating in `AP4_BitReader::ReadCache()`, reached from the AC-4 header constructor (local paths trimmed to repo-relative):

```text
==58320==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x116bb1ca01b8 ...
READ of size 1 at 0x116bb1ca01b8 thread T0
    #0 AP4_BitReader::ReadCache                              Source/C++/Core/Ap4Utils.cpp:447
    #1 AP4_BitReader::ReadBits                               Source/C++/Core/Ap4Utils.cpp:467
    #2 AP4_Dac4Atom::Ac4Dsi::PresentationV1::ParsePresentationV1Info  Source/C++/Core/Ap4Dac4Atom.cpp:1329
    #3 AP4_Ac4Header::AP4_Ac4Header                          Source/C++/Codecs/Ap4Ac4Parser.cpp:130
    #4 AP4_Ac4Parser::FindFrame                              Source/C++/Codecs/Ap4Ac4Parser.cpp:405
    #5 AddAc4Track                                           Source/C++/Apps/Mp4Mux/Mp4Mux.cpp:868
    #6 main                                                  Source/C++/Apps/Mp4Mux/Mp4Mux.cpp:2368
SUMMARY: AddressSanitizer: heap-buffer-overflow Source/C++/Core/Ap4Utils.cpp:447 in AP4_BitReader::ReadCache
```

## Impact

- **Denial of service** — the out-of-bounds read crashes `mp4mux` (and any host process embedding the AC-4 parser) when it ingests the crafted file.
- **Potential information disclosure** — the over-read pulls bytes from **adjacent heap memory** into the parse, which (depending on allocator layout) may influence parsed output or leak residual heap contents.

> [!danger] Remote reachability via media pipelines
> The report classifies this as a **remote** attack: the attacker only needs to get a crafted `.ac4` file **processed** by a Bento4-based muxing service. No local access or authentication is required where untrusted media is accepted.

## Timeline

| Date       | Event                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------- |
| 2026-04-19 | Reported via [Bento4#1060](https://github.com/axiomatic-systems/Bento4/issues/1060)           |
| 2026-04-27 | Fix / patched release [commit](https://github.com/axiomatic-systems/Bento4/pull/1062/commits) |
| 2026-06-05 | **CVE-2026-38232** assigned                                                                   |

## References

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [Bento4 issue #1060](https://github.com/axiomatic-systems/Bento4/issues/1060)
- [Bento4 repository (axiomatic-systems/Bento4)](https://github.com/axiomatic-systems/Bento4)
