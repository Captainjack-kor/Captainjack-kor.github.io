---
title: "Chafa — Integer overflow and OOB write with big output size in the Sixel Renderer"
severity: High
type: CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow)
affected_component: "libchafa / chafa CLI"
affected_version: "≤ 1.18.1"
patched_version: "1.18.2"
affected_file: chafa/internal/chafa-sixel-renderer.c
affected_function: build_sixel_row_worker (line 387)
reporter: Hyeontaek Lim (Captainjack)
date: 2026-04-14
---

| | |
| --- | --- |
| **Severity** | <span class="sev">High</span> *(self-assessed)* |
| **Type** | CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow) |
| **Affected** | `libchafa` / `chafa` &le; 1.18.1 |
| **Patched** | 1.18.2 |
| **Affected file** | `chafa/internal/chafa-sixel-renderer.c` → `build_sixel_row_worker()` (line 387) |
| **Release** | [v1.18.2](https://github.com/hpjansson/chafa/releases/tag/1.18.2) |

## Summary

A signed integer-overflow vulnerability exists in the **Sixel renderer** of Chafa (`libchafa`). When an image is rendered in Sixel mode (`--format sixel`) with a large output width, a **32-bit signed multiplication overflows** before the result is passed to `g_malloc()`.

The wrapped value can become a **small positive integer**, producing an **undersized heap allocation**. The Sixel encoder then writes far more data than was allocated — an **out-of-bounds heap write** with partially attacker-influenced contents.

> [!danger] Remote attack surface via `libchafa`
> When `libchafa` is embedded in a service that thumbnails or renders **untrusted images** (web apps, file managers, chat-preview pipelines), a crafted image combined with a large rendering width can trigger the overflow remotely — potentially leading to **remote code execution** depending on the heap layout and platform.

## Details

### Root cause — allocation size computed in 32-bit signed arithmetic

The output-buffer size is computed entirely with `gint` (32-bit signed) before the implicit conversion to `g_malloc()`'s `gsize` (64-bit unsigned) parameter:

```c
// chafa/internal/chafa-sixel-renderer.c:387
sixel_ansi = p = g_malloc(256 * (ctx->sixel_renderer->width + 5) * n_sixel_rows + 1);
```

Because `256 * (width + 5) * n_sixel_rows + 1` is evaluated in 32-bit signed arithmetic, overflow occurs *before* the value is widened to `gsize`. The converted result can be:

- a **very large** number → out-of-memory abort (DoS), or
- a **small positive** number → undersized allocation → **heap buffer overflow**.

A related allocation at line 384 multiplies the same unchecked `width`, but its arithmetic differs:

```c
// chafa/internal/chafa-sixel-renderer.c:384
srow.data = g_malloc(sizeof(SixelData) * ctx->sixel_renderer->width);
```

Here `sizeof(SixelData)` is a `gsize` (64-bit), so `width` is promoted and the multiplication is performed in **64-bit** arithmetic. For a positive `width` this does **not** wrap in 32-bit — it merely requests a large allocation (a DoS lever, not an undersized buffer). It only turns dangerous if `width_pixels` (computed in `gint` at `chafa-canvas.c:542`) has already wrapped negative, in which case the negative value converts to a huge `gsize`. The undersized-allocation primitive is therefore specific to **line 387**.

### Width propagation — user input reaches the allocation unchecked

User-supplied `--size W x H` flows straight to `canvas->config.width`, is multiplied by `cell_width`, and forwarded to the Sixel renderer with **no upper-bound validation** anywhere along the path:

```c
// chafa/chafa-canvas.c:542
canvas->width_pixels = canvas->config.width * canvas->config.cell_width;

// chafa/chafa-canvas.c:448
canvas->pixel_renderer = chafa_sixel_renderer_new(canvas->width_pixels, ...);
```

```text
--size 4200000x12
    ↓
canvas->config.width        = 4,200,000
    ↓
width_pixels = width × cell_width        (gint multiply, no clamp)
    ↓
sixel_renderer->width       = 4,200,000 (or a multiple)
    ↓
build_sixel_row_worker()    → overflow at the g_malloc() expression
```

### Overflow arithmetic — large-value path (DoS)

With `width = 4,200,000`, `n_sixel_rows = 2`:

```text
256 × (4,200,000 + 5) × 2 + 1 = 2,150,402,561
INT_MAX                        = 2,147,483,647

Overflow:  2,150,402,561 > INT_MAX
gint (wrap):   -2,144,564,735
→ gsize:       0xFFFFFFFF802C8A01   → huge allocation → OOM
```

### Overflow arithmetic — "magic width" path (heap overflow)

A carefully chosen width wraps the expression to a **small positive integer**, so a tiny buffer is allocated while the encoder writes megabytes:

```text
Target:  256 × (w + 5) × 2  ≡  small_value (mod 2^32)

Example: w = 8,388,604   (= 2^23 − 4)
  512 × (8,388,604 + 5) = 512 × 8,388,609 = 2^32 + 512 = 4,294,967,808
  + 1                                    → 4,294,967,809
  truncated to 32-bit (mod 2^32)         → 513
  g_malloc(513)                          ← allocated (just 513 bytes)
  actual write ≈ 256 × 8,388,609 × 2 ≈ 4.29 GB of sixel data
  → heap buffer overflow of several GB
```

### Write-primitive analysis

The bytes written past the buffer come from `build_sixel_row_ansi()`, which encodes pixel data as Sixel escape sequences:

| Byte | Value | Source |
| --- | --- | --- |
| `$`  | 0x24 | Sixel carriage-return |
| `-`  | 0x2D | Sixel graphics newline |
| `#`  | 0x23 | Pen intro character |
| `;`  | 0x3B | Pen field separator |
| `0`–`9` | 0x30–0x39 | Decimal RGB values (0–100), pen index |
| `?`–`~` | 0x3F–0x7E | Sixel data characters |

The decimal RGB values (0–100) are derived directly from the input image's palette, giving an attacker who controls the image **partial influence over the overflow contents** — not a full arbitrary write, but enough to shape some of the overwritten bytes.

## Reproduction

### Build prerequisites

```bash
sudo apt-get install -y autoconf automake libtool pkg-config
sudo apt-get install -y libglib2.0-dev libfreetype6-dev
sudo apt-get install -y libavif-dev libheif-dev libjpeg-dev librsvg2-dev \
                        libtiff-dev libwebp-dev libjxl-dev
```

### Build with AddressSanitizer

```bash
./autogen.sh
CFLAGS="-fsanitize=address -g -O0" LDFLAGS="-fsanitize=address" ./configure
make -j$(nproc)
```

### PoC

> [!note] PoC withheld
> `poc.py` (the crafted-PNG generator) and the exact trigger command will be published after a CVE is assigned.

Once Chafa is built with AddressSanitizer, the crafted PNG is rendered in Sixel mode at the "magic width" that wraps the allocation size to a small positive value (see the arithmetic above):

```bash
# render the crafted image at the overflow-triggering width
chafa --format sixel --size <magic-width>x12 crash.png
```

AddressSanitizer reports a **heap-buffer-overflow WRITE** originating in `build_sixel_row_ansi()` and reached from `build_sixel_row_worker()` (`chafa/internal/chafa-sixel-renderer.c:387`): the undersized `g_malloc()` buffer is overrun as the Sixel encoder emits far more data than was allocated.

## Impact

- **Out-of-bounds heap write** with partially attacker-influenced contents (Sixel-encoded palette bytes), corrupting adjacent heap data and potentially leading to **remote code execution** depending on heap layout and platform.
- **Denial of service** via the large-value path — an oversized rendering width forces a multi-gigabyte allocation and an out-of-memory abort.

> [!danger] Untrusted-image rendering pipelines
> Any service that embeds `libchafa` to thumbnail or preview **untrusted images** with a caller-controlled output width (web apps, file managers, chat-preview workers) is remotely exposed: a crafted image combined with a large width reaches the vulnerable allocation with **no upper-bound check** anywhere along the path.

## Timeline

| Date       | Event                  |
| ---------- | ---------------------- |
| 2026-04-14 | Vulnerability reported |
| —          | Patched in `1.18.2`    |
| TBD        | CVE assigned           |

## References

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- [Chafa 1.18.2 release](https://github.com/hpjansson/chafa/releases/tag/1.18.2)
