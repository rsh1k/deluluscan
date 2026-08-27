# Running a local model on a low-capacity device (and wiring it to Deluluscan)

This is a concrete, measured plan for **your machine** and the general case. It
answers: can the model run here, how to make it run smoothly under WSL without an
NVIDIA GPU, and how Deluluscan uses it.

## Your device (measured)
| | |
|---|---|
| CPU | Intel **i5-1235U** (Alder Lake) — WSL sees **4 vCPUs / 2 cores** |
| ISA | **AVX2 + FMA + F16C + AVX-VNNI**, VAES, GFNI — **no AVX-512** |
| RAM (in WSL) | **~7.8 GB** total, ~6.9 GB free (+ 4 GB swap) |
| Disk free | **~888 GB** (weights are not the constraint; RAM is) |
| GPU | Microsoft Basic Render Driver only — **no `/dev/dri`**, so the Intel iGPU is **not** available for compute in WSL → **CPU-only inference** |
| OS | WSL2, kernel 6.18 |

## Verdict on the "Qwen3 ~27B uncensored" model
- A **dense 27B** at Q4_K_M is ~16–17 GB of weights and needs ~18–20 GB RAM to run
  well. **It will not fit in 8 GB** — it would swap to disk and crawl at seconds
  *per token*. Don't run a dense 27B here.
- Two paths that **do** work on this machine:

### Path A — MoE model + your `potatomaxx` (the intended fit)
Your own tool [`potatomaxx`](https://github.com/Quilzo/potatomaxx) exists precisely
for this: it makes a **Mixture-of-Experts** model "run on hardware that cannot hold
it" by streaming experts from disk with queue-depth-optimized I/O (it reports ~33×
read throughput) and per-expert precision — and it was **tested on this exact
i5-1235U / 7.6 GB machine**. So the right model shape here is a **Qwen3 MoE** (e.g.
**Qwen3-30B-A3B** — ~30B total but only **~3B active per token**), repacked by
potatomaxx and run under llama.cpp:

```bash
# 1) build potatomaxx (Rust, std-only)
git clone https://github.com/Quilzo/potatomaxx && cd potatomaxx && make && sudo make install
# 2) advise: does this model fit this device, and how to pack it?
potatomaxx advise --model qwen3-30b-a3b-Q4_K_M.gguf
# 3) repack for disk-resident streaming (byte-identical weights, optimized layout)
potatomaxx pack --in qwen3-30b-a3b-Q4_K_M.gguf --out qwen3-30b-a3b.packed.gguf
potatomaxx verify --in qwen3-30b-a3b.packed.gguf
# 4) serve with llama.cpp's OpenAI-compatible server (CPU)
llama-server -m qwen3-30b-a3b.packed.gguf -t 4 --ctx-size 4096 --host 127.0.0.1 --port 8080
```
Because only ~3B params are active per token, a well-streamed MoE-A3B is far more
tractable on 8 GB than a dense 27B — this is potatomaxx's whole reason to exist.

### Path B — a small dense model (simplest, no repacking)
For a no-fuss backend, run a **3B–8B dense** model at **Q4_K_M** via Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh          # installs ollama
ollama serve &                                          # WSL may need this (no systemd)
ollama pull qwen2.5:7b        # ~4.7 GB  (or: llama3.1:8b, phi4-mini, qwen2.5:3b for more headroom/speed)
```
Expect **~8–15 tokens/s** for a 7B Q4 on this CPU class — plenty for Deluluscan's
short, structured triage/reasoning prompts. Drop to a 3B for snappier latency.

## Making CPU inference fast (no NVIDIA)
Sources: llama.cpp CPU internals; Ollama/llama.cpp CPU benchmarks 2026.
- **Quantize** to **Q4_K_M** — the size/quality sweet spot; AVX2 int8 kernels
  (this CPU has AVX-VNNI) give ~4–8× over scalar. 
- **Threads = physical cores.** Set `-t 4` (llama.cpp) / `OLLAMA_NUM_THREAD=4`.
  Going above the core count on an SMT CPU **hurts** throughput.
- **Small context** (`--ctx-size 4096`) and **mmap** (default on) keep RAM down.
- **Give WSL more RAM** if your host has it (i5-1235U laptops are often 16 GB).
  Create `C:\Users\<you>\.wslconfig`:
  ```ini
  [wsl2]
  memory=12GB
  processors=4
  swap=8GB
  ```
  then `wsl --shutdown` and reopen. More RAM = a bigger model fits without swapping.
- **iGPU:** the Intel Iris Xe is **not** exposed to WSL (no `/dev/dri`), so
  llama.cpp's Vulkan/SYCL GPU backends won't help here — CPU is the reliable path.
  (On native Linux or Windows-native llama.cpp you could use the Vulkan backend on
  the iGPU; under WSL, stay on CPU.)
- **llama.cpp ≥ Ollama** for raw CPU speed (~15–25% via explicit AVX2 build + Q4_K_M
  + thread tuning); Ollama is the easier on-ramp and uses llama.cpp underneath.

## Wiring the local model into Deluluscan (already supported — WS-1)
No new code needed — the provider layer already speaks to local models:

```bash
# Use the local model as the SCANNER's reasoning/triage backend:
python3 -m deluluscan.cli --config config.yaml --ai ollama --ai-model qwen2.5:7b
# ...or an OpenAI-compatible llama-server (Path A):
python3 -m deluluscan.cli --config config.yaml --ai openai_compat \
    --ai-endpoint http://127.0.0.1:8080/v1 --ai-model qwen3-30b-a3b

# Pentest an LLM app you're building, using the same local model as the tester:
python3 -m deluluscan.llm --provider ollama --model qwen2.5:7b --url http://127.0.0.1:8080/api/chat
```
`redact_prompts` is on by default, but a **local** model (ollama / llama-server)
never egresses data anyway — ideal for sensitive work.

## Responsible-use note
An "uncensored" model changes nothing about Deluluscan's guarantees: the AI is
**advisory** (the live differential verifier stays authoritative), the tool
**confirms to proof but never weaponizes**, and the **loopback/RFC1918 scope gate**
stands — use it only against web apps you own or are authorized to test.

## Verified on THIS device (measured)
Ran end-to-end on the i5-1235U / WSL / 4 vCPU / no-GPU box, CPU-only:
- Installed Ollama v0.32.15 in userspace (no sudo); pulled `qwen2.5:0.5b` (397 MB).
- **Raw inference: ~30 tokens/s on CPU** (correct answer on "what is SQL injection").
- **Deluluscan WS-1 provider** (`--provider/--ai ollama`) connected and completed
  against the local model (fully offline, no egress).
- **WS-3 LLM pentest against the local model** (`python3 -m deluluscan.llm --provider
  ollama --model qwen2.5:0.5b`) returned **6 findings (5 confirmed)** across OWASP
  LLM01/LLM05/LLM06 — the small model is highly injectable, and each hit was
  live-reproduced with captured request/response evidence. Pipeline verified.
- A 0.5 B model reasons weakly (use it to prove the pipeline); step up to a 3–7 B
  Q4_K_M (or a Qwen3-MoE via potatomaxx) for real scanner-reasoning quality.

## Accelerating an uncensored model with potatomaxx (the RIGHT model matters)
**Key finding (verified against potatomaxx's source): potatomaxx needs NO code
changes to handle Qwen3-MoE.** Its `moe.rs` detects experts *generically* by the
standard GGUF tensor fragments (`ffn_gate_exps` / `ffn_up_exps` / `ffn_down_exps`,
router `ffn_gate_inp` / `exp_probs_b`) and reads `n_experts` from the tensor axis —
it keys on structure, not model name. Qwen3-30B-A3B uses exactly that layout.

**What actually determines whether potatomaxx can help is the model *architecture*:**
- The blog's `Qwen3.8-27B-Uncensored` is a **DENSE** model — every one of its
  ~10.5 GB of weights is read for *every* token. potatomaxx (which streams only the
  *active experts* of an MoE) cannot accelerate a dense model; the ceiling is
  ~disk-bandwidth ÷ full-model-size ≈ **<1 tok/s** on 8 GB. This is architecture, not
  software — no potatomaxx change fixes it.
- The fix is to use an **uncensored MoE**:
  **[`huihui-ai/Qwen3-30B-A3B-abliterated`](https://huggingface.co/huihui-ai/Qwen3-30B-A3B-abliterated)**
  (GGUF: `mradermacher/Qwen3-30B-A3B-abliterated-i1-GGUF`). 30B total but only **~3B
  active per token** → ~1 GB read/token → usable on 8 GB, and exactly potatomaxx's design point.

### Verified on THIS device (potatomaxx built + run, CPU-only)
`cargo build --release` succeeded in ~9 s. The full pipeline on a synthetic MoE:
`synth → analyse → advise → plan → pack → verify` all ran, reporting a **1.33×
predicted expert-read speedup** from layout repack (4/4 layers past threshold) and
`verify`: *"the repacked file holds exactly the original weights."*

### Recipe (once the MoE GGUF is downloaded)
```bash
PMX=~/potatomaxx-src/target/release/potatomaxx
M=Qwen3-30B-A3B-abliterated.i1-Q2_K.gguf                 # ~11GB MoE, ~3B active/token
$PMX inspect --model $M                                   # confirm MoE structure (n_experts)
$PMX probe   --dir . --out pmx-probe.json                 # device read-bandwidth surface
$PMX advise  --model $M --probe pmx-probe.json            # device-calibrated recommendations
$PMX plan    --model $M --trace <trace> --out plan.json   # (trace from a representative run)
$PMX pack    --model $M --plan plan.json --out $M.packed.gguf
$PMX verify  --model $M --repacked $M.packed.gguf --plan plan.json
# then serve the (packed) GGUF and point Deluluscan at it:
ollama create qwen3moe-unc -f <(printf 'FROM %s\n' "$PWD/$M.packed.gguf")
python3 -m deluluscan.cli --config config.yaml --ai ollama --ai-model qwen3moe-unc
```
Note potatomaxx's own honest caveat: the layout repack is one lever (~1.3×); the
bigger win is raising **I/O queue depth** at inference time (its 33× throughput
figure), which needs an inference runtime, not just a repacked file.

## Settled: the 30B MoE won't load on 8 GB — use a fitting uncensored model
Measured on-device: llama.cpp's memory pre-check **refuses** the 11 GB Q2_K MoE:
`projected to use 10840 MiB of host memory vs. 7942 MiB total … unable to fit …
abort`. It is a hard RAM wall (not slow — it will not load). potatomaxx cannot move
this: it *reads/analyses* the real MoE fine (`inspect`: 48 layers × 128 experts), but
its footprint-reduction (`build-store`) needs potatomaxx's own inference runtime;
Ollama/llama.cpp only get its layout benefit, not the resident-set reduction. A 30B
MoE needs ≥ ~12–16 GB RAM (raise it via `.wslconfig`).

### Working uncensored setup on THIS 8 GB device (verified)
```bash
ollama pull huihui_ai/qwen2.5-abliterate:3b     # 1.9 GB, abliterated/uncensored
```
Measured: **cold load 6 s, ~12 tok/s on CPU** (no GPU), and Deluluscan drives it:
```bash
python3 -m deluluscan.cli --config config.yaml --ai ollama --ai-model huihui_ai/qwen2.5-abliterate:3b
python3 -m deluluscan.llm --provider ollama --model huihui_ai/qwen2.5-abliterate:3b --url <your chat app>
```
Step up to `huihui_ai/qwen2.5-abliterate:7b` (~4.7 GB Q4) for better reasoning if RAM
allows; the 3B is the comfortable fit here. For the *biggest* uncensored MoE, run it on
a machine with ≥16 GB RAM (or raise WSL memory) and then potatomaxx's streaming pays off.
