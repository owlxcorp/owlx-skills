---
name: reverse-engineer
description: Act as a world-class Reverse Engineer using the full radare2 ecosystem (r2, r2ai, r2frida, r2ghidra). Use this skill to analyze binaries, disassemble code, decompile logic, debug processes, instrument applications, and explain low-level concepts. Triggers on requests involving binary analysis, disassembly, decompilation, malware analysis, CTF challenges, AI-assisted RE, or tools like Radare2, Frida, Ghidra, or r2ai.
---

# Expert Reverse Engineering Pipeline

Execute reverse engineering tasks using a rigorous **Triage → Map → Lift → Verify → Instrument** pipeline.

## 0. Environment Setup & Tool Stack

Configure for maximum visibility before analysis.

### Recommended ~/.radare2rc

```
e scr.utf8 = true           # UTF-8 boxes/arrows
e asm.emu = true            # Show emulated register values in comments
e asm.var = true             # Show local variables in disassembly
e anal.hasnext = true        # Aggressive function detection
e bin.demangle = true        # Auto-demangle C++/Rust symbols
e scr.color = 3              # Truecolor mode
```

### Tool Stack

| Tool | Purpose | Install |
|------|---------|---------|
| `r2` | Interactive disassembly, analysis, debugging | `brew install radare2` / `apt install radare2` |
| `rabin2` | Static binary metadata (headers, imports, strings, sections) | Bundled with r2 |
| `rasm2` | Assemble/disassemble individual instructions | Bundled with r2 |
| `radiff2` | Binary diffing | Bundled with r2 |
| `rahash2` | Hashing and checksums | Bundled with r2 |
| `r2ghidra` | Ghidra decompiler as r2 plugin | `r2pm -ci r2ghidra` |
| `r2dec` | Lightweight r2 decompiler | `r2pm -ci r2dec` |
| `r2ai` | AI integration (native C plugin) | `r2pm -Uci r2ai` |
| `decai` | AI-assisted decompilation (r2js) | `r2pm -Uci decai` |
| `r2frida` | Frida dynamic instrumentation bridge | `r2pm -ci r2frida` |
| `retdec` | RetDec decompiler plugin | `r2pm -ci retdec` |

Verify: `r2 -v && rabin2 -v`

### r2ai API Key Setup

For remote LLM APIs, store keys in home directory:

```bash
echo "sk-..." > ~/.r2ai.openai-key && chmod 600 ~/.r2ai.openai-key
echo "sk-ant-..." > ~/.r2ai.anthropic-key && chmod 600 ~/.r2ai.anthropic-key
```

Configure model in `~/.radare2rc`:

```
r2ai -e api=anthropic
r2ai -e model=claude-sonnet-4-20250514
r2ai -e max_tokens=64000
```

## Phase 1: Deep Triage & Capability Mapping

Don't just run `rabin2 -I`. Map the binary's full capability surface.

```bash
# Identity: format, arch, bits, endianness, OS, compiler, security (NX/PIE/Canary)
rabin2 -I <binary>

# Behavior profiling via imports
#   Network: socket, connect, bind, send, recv
#   File I/O: fopen, read, write, access, unlink
#   Process: fork, exec, system, popen
#   Crypto: EVP_*, AES_*, SHA_*
#   Anti-debug: ptrace, IsDebuggerPresent, sigaction
rabin2 -i <binary>

# Strings (secrets, URLs, error messages, format strings)
rabin2 -z <binary>          # data section only
rabin2 -zz <binary>         # all strings (catches obfuscated/encoded)

# Structure: sections, entry points, exports, libraries, relocations
rabin2 -S <binary>          # sections
rabin2 -e <binary>          # entry points
rabin2 -E <binary>          # exports
rabin2 -l <binary>          # linked libraries
rabin2 -R <binary>          # relocations
rabin2 -H <binary>          # headers

# C++/ObjC/Java: classes and RTTI
rabin2 -c <binary>

# Debug/DWARF info (massively simplifies RE if present)
rabin2 -d <binary>

# Everything at once
rabin2 -g <binary>

# Hash for identification
rahash2 -a md5,sha256 <binary>
```

**Key triage questions:**
1. Architecture? (x86, x86_64, ARM, MIPS, PPC)
2. Stripped or has symbols?
3. Static or dynamic linking?
4. What capabilities do imports reveal? (network? crypto? anti-debug?)
5. Interesting strings? (hardcoded creds, URLs, error messages)
6. Packed/obfuscated? (high entropy sections, UPX, custom packers)

### Advanced Identification

**Stripped binary** → Apply Zignatures (FLIRT-style) to identify static library functions:

```
r2 -A <binary>
z*                    # Manage/apply signatures
zfs <sig_file>        # Load signature file
```

**C++ target** → Inspect virtual tables and RTTI for class hierarchy:

```
av                    # Analyze vtables
avr                   # Recover RTTI at address
avj                   # Vtables as JSON
```

## Phase 2: Static Analysis & Disassembly

### Open and Analyze

```bash
r2 <binary>           # Read-only (default)
r2 -w <binary>        # Write mode (for patching)
r2 -A <binary>        # Auto-analyze (aa)
r2 -AA <binary>       # Deep analysis (aaa)
```

### Analysis Commands — Understand the Depth

Do not blindly run `aaa`. Choose the right depth:

```
aa          # Basic: symbols + entry points (fast)
aaa         # Standard: aa + type propagation + more (recommended)
aab         # Nucleus algorithm — vital for stripped binaries
aac         # Analyze function call destinations
aaf         # Analyze all function calls
aar         # Analyze data references (lenient)
aad         # Analyze pointer-to-pointer references
aaaa        # Experimental deep analysis (slow, thorough)
```

### Function Management

```
afl         # List all discovered functions
aflj        # List functions as JSON
afl=        # ASCII-art function range bars
afn <name> [addr]  # Rename function
afvn <old> <new>   # Rename local variable
afvt <name> <type> # Retype variable (e.g., afvt local_8h char *)
afi         # Function info (size, complexity, xrefs)
afb         # List basic blocks
afCc        # Cyclomatic complexity
```

### Navigate and Disassemble

```
s main            # Seek to main (or sym.main)
s <addr>          # Seek to address
s- / s+           # Undo/redo seek

pdf               # Disassemble current function
pdf @ main        # Disassemble main
pd 20             # Print 20 instructions at current position
pd 20 @ 0x401000  # Print 20 instructions at address
pdr               # Disassemble function recursively (follow calls)
pds               # Function summary (calls + strings only)
pdc               # Pseudo-decompiler (all architectures, no plugins)

# Cross-references — critical for control flow
axt [addr]        # Xrefs TO this address (who calls/references this?)
axf [addr]        # Xrefs FROM this address (what does this call/reference?)
axtg              # Generate xref graph commands
axg [addr]        # Show xref graph to reach an address
```

### Visual Modes

```
V                 # Visual mode (hex, disasm, debug views)
VV                # Graph mode (control flow graph) — critical for complex logic
V!                # Visual Panels (IDA-like multi-panel layout)
p / P             # Rotate view modes
v                 # Code analysis menu (function browser)
:                 # Enter r2 command from visual mode
q                 # Exit visual mode
hjkl              # Navigate (vim-style)
x                 # Show xrefs
Tab               # Switch panels (in V!)
```

### Searching

```
/ <string>        # Search for string
/x <hex>          # Search for hex bytes
/c <asm>          # Search for assembly instruction pattern
/a <asm>          # Assemble and search for bytes
/R                # Search for ROP gadgets
iz                # List strings in data section
izz               # List ALL strings in binary
```

### Binary Info (inside r2)

```
ii                # Imports
iI                # Binary info
ie                # Entry points
iS                # Sections
ir                # Relocations
iz                # Strings (data section)
```

## Phase 3: AI-Augmented Decompilation

Modern RE uses LLMs to accelerate understanding. Use the full decompiler stack.

### Built-in Pseudo-Decompiler (pdc)

Available for ALL architectures, no plugins needed. Fast and verbose — good starting point and good LLM feed:

```
pdc               # Pseudo-decompile current function
pdc @ main        # Pseudo-decompile main
```

### r2ghidra (pdg) — Recommended for Quality

Install: `r2pm -ci r2ghidra`

```
pdg               # Decompile current function to C
pdg @ main        # Decompile main
pdgo              # Decompile with offset annotations (C lines → addresses)
pdga              # Side-by-side: disassembly | decompilation
pdgj              # JSON output (for scripting)
```

Configure:

```
e r2ghidra.casts=true       # Show type casts
e r2ghidra.lang=x86:LE:64:default  # Override arch detection
e r2ghidra.roprop=2         # Read-only constant propagation (0-4)
e r2ghidra.vars=true        # Use r2's variable analysis
e r2ghidra.timeout=120      # Decompilation timeout (seconds)
```

### r2dec (pdd) — Lightweight Alternative

Install: `r2pm -ci r2dec`

```
pdd               # Decompile current function
pdda              # Side-by-side: disassembly | decompilation
pddj              # JSON output
```

### r2ai — AI-Powered Analysis

Install: `r2pm -Uci r2ai`

```
r2ai -d "Explain what the current function does"
r2ai -d "List possible vulnerabilities in this function"
r2ai -d "Suggest better variable names for this function"
```

### decai — AI Decompilation Engine

Install: `r2pm -Uci decai`

```
decai -d              # AI-decompile current function
decai -dr             # Recursive: decompile function + all callees
decai -dd             # Force re-decompile (ignore cache)
decai -dD "with descriptive variable names"  # Decompile with extra query
decai -q "Explain what forkpty does in 2 lines"  # Quick question
decai -a "Find buffer overflows and propose a patch"  # Auto mode
decai -a "solve this crackme"  # Auto-solve
```

Configure decai:

```
decai -e api=anthropic        # or openai, ollama, mistral, gemini
decai -e model=claude-sonnet-4-20250514
decai -e lang=C               # Output language
decai -e cache=true            # Cache decompilation results
```

### Decompile All Functions (scripting)

```bash
r2 -qc 'aaa; afl~[0]' binary | while read fn; do
  r2 -qc "aaa; s $fn; pdg" binary
done > full_decompiled.c
```

## Phase 4: Reconstruction — From Pseudocode to Real C

Decompiler output is pseudocode, not compilable C. Transform it systematically.

### Reconstruction Checklist

1. **Map imports to headers**: `#include <stdio.h>`, `<stdlib.h>`, `<string.h>`, etc.
2. **Recover types**: Replace `int64_t param_1` with meaningful types (`char *filename`, `struct foo *ctx`)
3. **Name variables**: Use context clues (strings, API calls, comparisons) to name locals
4. **Name functions**: Use call patterns, strings, error messages to name `fcn.0040xxxx`
5. **Reconstruct structs**: Field access patterns (`*(param_1 + 0x8)`) → struct definitions
6. **Recover enums/constants**: Magic numbers → named constants (`0x7f454c46` → `ELF_MAGIC`)
7. **Simplify control flow**: Flatten goto-heavy output into if/else, for, while, switch
8. **Remove dead code**: Decompiler artifacts, unreachable blocks
9. **Verify correctness**: Compare behavior of reconstructed C vs original binary

### Struct Recovery Pattern

When you see repeated offset access from a pointer:

```c
// Decompiler output:
*(param_1 + 0)    = value1;
*(param_1 + 8)    = value2;
*(param_1 + 0x10) = value3;

// Reconstruct as:
typedef struct {
    uint64_t field_0;     // offset 0x00
    uint64_t field_8;     // offset 0x08
    uint64_t field_10;    // offset 0x10
} my_struct_t;
```

### Manual Type Application in r2

```
# Rename and retype variables
afvn local_4h filename
afvt local_4h char *

# Define struct from C syntax
"td struct user { int id; char name[64]; int role; };"

# Apply struct type to variable
afvt local_8h struct user *

# Load types from a C header
to header.h

# Apply type to function signature
afsr <function> <new_signature>
```

### C++ Vtable Reconstruction

```
av                    # Analyze all vtables
avj                   # Vtables as JSON
avr                   # Recover RTTI at address

# Reconstructed vtable → C struct:
# typedef struct {
#     void (*method1)(void *this);
#     void (*method2)(void *this, int arg);
# } MyClass_vtable;
```

## Phase 5: Dynamic Analysis & Instrumentation

### Debugging (Native)

```bash
r2 -d <binary>           # Open in debugger mode
r2 -d -A <binary>        # Debug + auto-analyze
```

```
db <addr>         # Set breakpoint
dc                # Continue execution
ds                # Step instruction
dso               # Step over
dr                # Show registers
dr rax            # Show specific register
drr               # Show registers with references
dm                # Show memory maps
px 64 @ rsp       # Hex dump 64 bytes at stack pointer
dbt               # Show backtrace
```

### r2frida — Dynamic Instrumentation Bridge

Inject Frida scripts directly from r2. Superior for mobile, obfuscated, or packed targets.

```bash
r2 frida://<pid>          # Attach to running process by PID
r2 frida://0              # Spawn local process
r2 frida://usb//<app>     # Attach to mobile app over USB
```

Inside r2frida session:

```
\i                        # List imports/exports via Frida
\il                       # List loaded libraries
\dt <symbol>              # Trace function calls (e.g., \dt recv)
\dt java.lang.String      # Trace Java methods (Android)
\di0 <addr>               # Intercept function at addr, log args
\. script.js              # Inject and run custom Frida JS script
:.                        # Run r2 commands inside the target process
\dc                       # Continue after intercepting
```

### Heap Analysis (Exploit Development)

Analyze glibc heap layout for use-after-free, double-free, heap overflow:

```
dmh                       # List heap chunks
dmhg                      # Graph heap layout (visual)
dmhc @ <addr>             # Inspect malloc_chunk struct at address
dmhb                      # List heap bins (fast, unsorted, small, large)
dmht                      # Show tcache entries
```

### ESIL Emulation (Safe Mode for Malware)

Run code without native execution — safe for malware analysis:

```
aei               # Initialize ESIL VM
aeim              # Initialize ESIL memory/stack
aeip              # Set instruction pointer to entry/current
aes               # Step one instruction
aeso              # Step over
aer               # Show ESIL registers
aecu <addr>       # Continue until address
```

### Binary Patching

```bash
r2 -w <binary>           # Open in write mode
```

```
wa nop @ 0x401234         # Write NOP at address
"wa jmp 0x40abcd" @ addr  # Write jump instruction
wx 9090 @ 0x401234        # Write raw hex bytes
wao nop @ addr            # NOP current instruction
wao jz @ addr             # Change conditional jump type
```

### Binary Diffing

```bash
radiff2 binary_v1 binary_v2           # Basic diff
radiff2 -c binary_v1 binary_v2        # Code diffing
radiff2 -g main binary_v1 binary_v2   # Graph diff of main function
```

## Phase 6: Automation (r2pipe)

Script repetitive tasks for batch analysis.

```python
import r2pipe

r2 = r2pipe.open("/path/to/binary")
r2.cmd("aaa")

# List all functions
functions = r2.cmdj("aflj")
for f in functions:
    print(f"{f['name']} at {f['offset']:#x}, size={f['size']}")

# Decompile a function
r2.cmd("s main")
print(r2.cmd("pdg"))

r2.quit()
```

## Quick Reference — One-Liners

| Intent | Command |
|--------|---------|
| Explain function with AI | `r2ai -d "Explain current function"` |
| AI-decompile with callees | `decai -dr` |
| Auto-solve crackme (AI) | `decai -a "solve this crackme"` |
| Find dangerous calls | `aaa; axt @ sym.imp.system` |
| Find buffer overflows (AI) | `decai -a "Find buffer overflows and propose a patch"` |
| Decompile main to C | `r2 -qc 'aaa; s main; pdg' binary` |
| Extract all strings | `rabin2 -zz binary` |
| Full binary triage | `rabin2 -I binary && rabin2 -z binary && rabin2 -i binary` |
| Diff two binaries | `radiff2 -c old.bin new.bin` |
| Trace Java methods (Android) | `r2 frida://<pid>` then `\dt android.app.Activity` |
| Patch instruction to NOP | `wao nop` |
| Search for ROP gadgets | `/R` |
| Heap chunk analysis | `dmh` |
| List biggest functions | `afl~[2] | sort -rn | head` |

## r2 Self-Documentation

r2 is fully self-documenting. Append `?` to any command prefix:

```
?              # Top-level help (all command families)
a?             # Analysis commands
p?             # Print commands
pd?            # Print disassembly subcommands
af?            # Analyze function commands
e??anal.       # All analysis config variables
e??r2ghidra.   # r2ghidra config variables
decai -h       # decai help
r2ai -h        # r2ai help
```

## Safety Protocols

1. **Sandboxing** — Always run malware in a VM or use ESIL emulation (`ae` commands)
2. **Backups** — Work on copies (`cp target.bin target.work`)
3. **Snapshots** — Snapshot VMs before dynamic analysis
4. **Legal** — Only reverse engineer binaries you have legal authorization to analyze
