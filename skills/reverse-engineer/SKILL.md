---
name: reverse-engineer
description: >-
  Reverse engineer native binaries (ELF, PE, Mach-O) into readable source code using radare2, Ghidra, and companion tools.
  Use when the user asks to disassemble, decompile, analyze, or reverse engineer a binary, executable, shared library,
  firmware image, or object file. Also use when asked to find vulnerabilities in binaries, solve crackmes/CTFs, extract
  strings or symbols, understand unknown executables, reconstruct C source from machine code, or perform binary diffing.
  Triggers on mentions of radare2, r2, Ghidra, disassembly, decompilation, binary analysis, reverse engineering, RE,
  or malware analysis.
  ALSO trigger when the user provides or references ANY binary file (.exe, .dll, .so, .dylib, .o, .elf, .apk, .ipa,
  .wasm, .bin, .fw, .img, .dex, .class, .jar, .macho, .ko, .sys, .drv, .ocx, .cpl) and asks questions like:
  "what does this do", "how does this work", "decompile this", "analyze this", "is this safe", "what functions does
  this have", "extract strings", "find the password", "crack this", "patch this", "bypass this check", "what API calls
  does it make", "what does this function do", "show me the source code", "convert to C", "convert to source",
  "understand this binary", "inspect this", "what is this file", "explain this executable", "how does this app work",
  "what's inside this", "find vulnerabilities", "security audit this binary", "what malware does this contain",
  "trace this program", "hook this function", "intercept calls", "debug this", "step through this".
  Supports ALL compiled languages: C, C++, Rust, Go, Dart/Flutter AOT, .NET NativeAOT, Swift, Objective-C,
  Java/Kotlin (Android), or unknown.
---

# Expert Reverse Engineering Pipeline

Reverse engineer **any** compiled binary into readable, reconstructed source. Supports all compiled languages and architectures.

## Quick Start — What Does the User Want?

**Read this first.** Match the user's intent to the right workflow, then execute it. Most users won't use RE terminology — interpret their intent.

### "Decompile this" / "Show me the source" / "Convert to C"
→ Full decompilation pipeline:
```bash
# 1. Triage: what is it?
rabin2 -I <binary>
# 2. Detect source language (see Language Fingerprinting in Phase 1)
rabin2 -zz <binary> | grep -iE "go\.build|runtime\.|_ZN|core::|_kDart|System\.|objc_msg|swift_" | head -10
# 3. Analyze
r2 -AA <binary>
# 4. Decompile (use pdg for quality, pdc for speed)
pdg @ main
# 5. For full binary: script all functions (Phase 3)
```

### "What does this binary do?" / "How does this work?" / "Explain this"
→ Behavioral triage — fast overview without full decompilation:
```bash
rabin2 -I <binary>                    # Identity: format, arch, security
rabin2 -z <binary>                    # Strings: secrets, URLs, messages
rabin2 -i <binary>                    # Imports: what APIs does it call?
rabin2 -E <binary>                    # Exports: what does it expose?
r2 -qc 'aaa; pds @ main' <binary>    # Summary: calls + strings in main
r2 -qc 'aaa; afl' <binary>           # Function list: scope of code
```
Then explain findings in plain language. Use `r2ai -d "Explain current function"` for AI-assisted explanation of key functions.

### "Is this safe?" / "Find vulnerabilities" / "Malware analysis"
→ Security-focused triage:
```bash
rabin2 -I <binary>                    # Security: NX? PIE? Canary? RELRO?
rabin2 -i <binary> | grep -iE "system|exec|popen|ptrace|connect|socket|recv|send|crypt|chmod|unlink|fork"
rabin2 -z <binary> | grep -iE "http|password|key|secret|token|admin|root|shell|/bin/"
r2 -qc 'aaa; axt @ sym.imp.system; axt @ sym.imp.execve' <binary>
```
Use `decai -a "Find buffer overflows and propose a patch"` for AI-powered vulnerability scanning. Always run untrusted binaries in a VM or use ESIL emulation.

### "Find the password" / "Solve this crackme" / "Bypass this check"
→ CTF/crackme workflow:
```bash
r2 -AA <binary>
pdf @ main                            # Read main logic
# Look for: cmp/test before conditional jumps, string comparisons
# Find comparison targets:
axt @ str.correct                     # Who references "correct"?
axt @ str.wrong                       # Who references "wrong"?
# AI assist:
decai -a "solve this crackme"
# Patch approach: change conditional jump
wao jmp @ <cmp_addr>                  # Force success branch
```

### "Extract strings / symbols / imports"
→ Static metadata extraction:
```bash
rabin2 -z <binary>                    # Data section strings
rabin2 -zz <binary>                   # ALL strings (wide, encoded)
rabin2 -i <binary>                    # Imports
rabin2 -E <binary>                    # Exports
rabin2 -S <binary>                    # Sections
rabin2 -l <binary>                    # Linked libraries
rabin2 -c <binary>                    # Classes (C++/ObjC/Java)
```

### "What does function X do?" / "Explain this function"
→ Targeted function analysis:
```bash
r2 -AA <binary>
afl~<name>                            # Find the function
s <function>                          # Seek to it
pdf                                   # Disassemble
pdg                                   # Decompile to C
r2ai -d "Explain what this function does, its parameters, return value, and side effects"
```

### "Trace / Hook / Intercept calls at runtime"
→ Dynamic instrumentation with r2frida:
```bash
r2 frida://<pid>                      # Attach to running process
\dt <symbol>                          # Trace function calls
\di0 <addr>                           # Intercept and log args
\. script.js                          # Inject custom Frida script
```

### "I have a .apk / Flutter app / .NET exe / Go binary"
→ Language-specific pipeline — jump directly to **Phase 5: Language-Specific RE** for the matching language, then proceed with Phases 3-4 for decompilation and reconstruction.

---

# Detailed Pipeline Reference

The Quick Start above handles most requests. Below is the full reference pipeline: **Triage → Identify Language → Map → Lift → Reconstruct → Verify → Instrument**.

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

### Core Tool Stack

#### radare2 (r2) — Foundation
Includes `r2`, `rabin2`, `rasm2`, `radiff2`, `rahash2`, `rafind2`.

| Platform | Install |
|----------|---------|
| macOS | `brew install radare2` |
| Ubuntu/Debian | `sudo apt install radare2` |
| Fedora/RHEL | `sudo dnf install radare2` |
| Arch | `sudo pacman -S radare2` |
| Windows | `choco install radare2` or download from https://github.com/radareorg/radare2/releases |
| From source (any) | `git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh` |

#### r2 Plugins (all platforms, via r2pm)
```bash
r2pm -ci r2ghidra        # Ghidra decompiler (pdg) — recommended
r2pm -ci r2dec            # Lightweight decompiler (pdd)
r2pm -Uci r2ai            # AI integration (native C)
r2pm -Uci decai           # AI decompilation engine (r2js)
r2pm -ci r2frida          # Frida instrumentation bridge
r2pm -ci retdec           # RetDec decompiler
```

#### Ghidra (standalone decompiler + plugin host)

| Platform | Install |
|----------|---------|
| macOS | `brew install --cask ghidra` |
| Ubuntu/Debian | Download from https://github.com/NationalSecurityAgency/ghidra/releases |
| Windows | Download from https://github.com/NationalSecurityAgency/ghidra/releases |
| Any (requires JDK 17+) | Extract zip, run `./ghidraRun` (Linux/macOS) or `ghidraRun.bat` (Windows) |

### Language-Specific Tools

#### Rust: `rustfilt` (symbol demangler)

| Platform | Install |
|----------|---------|
| Any (requires Rust) | `cargo install rustfilt` |
| Without Rust | `r2` built-in demangling: `e bin.demangle = true` handles Rust symbols |

#### Go: `GoReSym` (symbol recovery) + `redress` (source reconstruction)

| Platform | Install |
|----------|---------|
| Any (requires Go 1.18+) | `go install github.com/mandiant/GoReSym@latest` |
| Any (requires Go) | `go install github.com/goretk/redress@latest` |
| Pre-built binaries | https://github.com/mandiant/GoReSym/releases |

#### Dart/Flutter: `blutter` + `reFlutter` + `doldrums`

| Tool | Platform | Install |
|------|----------|---------|
| blutter | Linux/macOS | `git clone https://github.com/worawit/blutter && cd blutter && pip install -r requirements.txt` |
| blutter | Windows | Same as above (requires Python 3.8+, CMake, Ninja, C++ compiler) |
| reFlutter | Any | `pip install reflutter` |
| doldrums | Any | `git clone https://github.com/nickcano/doldrums` (version-specific) |
| darter | Any | `git clone https://github.com/nickcano/darter` |

#### .NET: `ILSpy` + `dnSpy` + `ghidra-nativeaot`

| Tool | Platform | Install |
|------|----------|---------|
| ILSpy CLI | Any (.NET 8+) | `dotnet tool install -g ilspycmd` |
| ILSpy GUI | Windows | https://github.com/icsharpcode/ILSpy/releases |
| ILSpy GUI | macOS/Linux | https://github.com/nicknisi/AvaloniaILSpy/releases or use CLI |
| dnSpy | Windows | https://github.com/dnSpyEx/dnSpy/releases |
| dotPeek | Windows | https://www.jetbrains.com/decompiler/download/ |
| ghidra-nativeaot | Any (Ghidra plugin) | https://github.com/Washi1337/ghidra-nativeaot — copy to `Ghidra/Extensions/` |

#### Swift: `swift-demangle`

| Platform | Install |
|----------|---------|
| macOS | Bundled with Xcode (`xcrun swift-demangle`) |
| Linux | Bundled with Swift toolchain (`sudo apt install swift` or https://swift.org/download/) |
| Windows | Bundled with Swift toolchain (https://swift.org/download/) |
| Without Swift | `r2` handles Swift demangling: `e bin.demangle = true` |

#### Objective-C: `class-dump`

| Platform | Install |
|----------|---------|
| macOS | `brew install class-dump` |
| macOS (manual) | https://github.com/nygard/class-dump/releases |
| Linux/Windows | N/A — ObjC binaries are Mach-O only; use `rabin2 -c` inside r2 instead |

#### Java/Android: `jadx` + `apktool`

| Tool | Platform | Install |
|------|----------|---------|
| jadx | macOS | `brew install jadx` |
| jadx | Ubuntu/Debian | `sudo apt install jadx` or download from https://github.com/skylot/jadx/releases |
| jadx | Windows | Download from https://github.com/skylot/jadx/releases (zip with .bat launcher) |
| jadx | Any (requires JRE 11+) | Download release zip, run `bin/jadx` or `bin/jadx-gui` |
| apktool | macOS | `brew install apktool` |
| apktool | Ubuntu/Debian | `sudo apt install apktool` |
| apktool | Windows | Download from https://apktool.org/docs/install — wrapper .bat + jar |
| apktool | Any | `java -jar apktool.jar d app.apk` |

#### Python: `r2pipe` (scripting API)

| Platform | Install |
|----------|---------|
| Any | `pip install r2pipe` |

### Verify Installation

```bash
# Core
r2 -v && rabin2 -v

# Plugins (inside r2)
r2 -qc 'e asm.arch' --
r2pm -l                              # List installed plugins

# Language tools (check whichever you installed)
rustfilt --version 2>/dev/null
GoReSym -h 2>/dev/null
jadx --version 2>/dev/null
dotnet tool list -g | grep ilspy
swift-demangle --help 2>/dev/null || xcrun swift-demangle --help 2>/dev/null
```

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
4. **What source language was it compiled from?** (see Language Fingerprinting below)
5. What capabilities do imports reveal? (network? crypto? anti-debug?)
6. Interesting strings? (hardcoded creds, URLs, error messages)
7. Packed/obfuscated? (high entropy sections, UPX, custom packers)

### Language Fingerprinting

Identify the source language **before** deep analysis — it determines your entire toolchain.

| Indicator | Language | How to Detect |
|-----------|----------|---------------|
| `_cgo_`, `runtime.`, `go.buildid`, `.gopclntab`, `.gosymtab` | **Go** | `rabin2 -S binary \| grep -i go` or `rabin2 -z binary \| grep -i "go.buildid\|runtime\."` |
| `_ZN`, `std::`, `__cxa_`, `.rtti`, vtables | **C++** | `rabin2 -z binary \| grep -i "std::\|__cxa"`, `rabin2 -c binary` |
| `_$LT$`, `core::`, `alloc::`, `_ZN` with `h` suffix | **Rust** | `rabin2 -z binary \| grep -i "core::\|alloc::\|rustc"`, symbols have `h<hash>` suffix |
| `_kDartVmSnapshot`, `_kDartIsolateSnapshot`, Dart pool | **Dart/Flutter** | `rabin2 -z binary \| grep -i dart\|flutter`, `libapp.so` inside APK |
| `System.`, `coreclr`, `gc_heap`, `S_P_CoreLib` | **.NET NativeAOT** | `rabin2 -z binary \| grep -i "System\.\|coreclr\|S_P_"` |
| `.managed_native_aot`, ReadyToRun header | **.NET R2R** | `rabin2 -H binary`, look for R2R magic |
| Standard .NET PE with `#~`, `#Strings` streams | **.NET IL** | `rabin2 -I binary` shows `class: MSIL`, use ILSpy/dnSpy directly |
| `objc_msgSend`, `@selector`, `__objc_classlist` | **Objective-C** | `rabin2 -i binary \| grep objc`, `rabin2 -c binary` |
| `swift_`, `_$s`, `Swift.`, `swiftCore` | **Swift** | `rabin2 -l binary \| grep swift`, `rabin2 -z binary \| grep swift` |
| `_JAVA_`, `.dex`, `dalvik` | **Java/Android** | `file binary`, look for DEX/JAR/APK format |
| Clean C-style imports, libc only, no mangling | **C** | Process of elimination — no language-specific markers |

**Quick one-liner:**

```bash
# Detect source language from string/symbol fingerprints
rabin2 -zz binary | grep -iE "go\.build|runtime\.(go|newproc)|_ZN.*E$|std::|core::|alloc::|_kDart|flutter|System\.|coreclr|objc_msg|swift_|_\$s" | head -20
```

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

## Phase 4: Reconstruction — From Pseudocode to Source

Decompiler output is pseudocode, not compilable source. Transform it to the **original source language** (or C for unknown/C binaries).

### Reconstruction Checklist

1. **Identify source language** first (Phase 1 fingerprinting) — reconstruct into the original language
2. **Map imports to headers/modules**: `#include`, `use`, `import`, `using` as appropriate
3. **Recover types**: Replace `int64_t param_1` with meaningful types (language-specific: `&str`, `string`, `[]byte`, etc.)
4. **Name variables**: Use context clues (strings, API calls, comparisons) to name locals
5. **Name functions**: Use call patterns, strings, error messages to name `fcn.0040xxxx`
6. **Reconstruct structs/classes**: Field access patterns (`*(param_1 + 0x8)`) → struct/class definitions
7. **Recover enums/constants**: Magic numbers → named constants
8. **Simplify control flow**: Flatten goto-heavy output into idiomatic control flow
9. **Apply language idioms**: `Result<T,E>` for Rust, error returns for Go, async/await for Dart, etc.
10. **Verify correctness**: Compare behavior of reconstructed source vs original binary

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

## Phase 5: Language-Specific Reverse Engineering

After identifying the source language in Phase 1, apply these specialized workflows.

### C++ Binaries

C++ binaries contain vtables, RTTI, name-mangled symbols, exception handling, and templates.

```
# Ensure demangling is on
e bin.demangle = true

# Analyze vtables and class hierarchy
av                    # Discover all vtables
avj                   # Vtables as JSON
avr                   # Recover RTTI at address

# Demangle a symbol manually
iD cxx <mangled_name>

# List C++ classes
rabin2 -c <binary>

# Reconstruct vtable as C struct:
# typedef struct {
#     void (*dtor)(void *this);
#     void (*method1)(void *this, int arg);
#     void (*method2)(void *this, const char *str);
# } MyClass_vtable;
#
# typedef struct {
#     MyClass_vtable *vptr;  // first field is always vtable pointer
#     int field1;
#     char *field2;
# } MyClass;
```

**Key C++ patterns to recognize:**
- `this` pointer is always the first argument (RDI on x86_64, R0 on ARM)
- Virtual calls: `call [rax + offset]` where RAX points to vtable
- `__cxa_throw` / `__cxa_begin_catch` = exception handling
- `operator new` / `operator delete` = heap allocation
- Template instantiations create many nearly-identical functions

### Rust Binaries

Rust binaries are statically linked, heavily inlined, and use a unique mangling scheme.

```bash
# Demangle Rust symbols
rabin2 -z binary | rustfilt          # Pipe through rustfilt
echo "_ZN4core3fmt5write17h..." | rustfilt   # Single symbol
```

```
# Inside r2 — demangling is automatic with e bin.demangle = true
e bin.demangle = true

# Rust-specific: look for panic/unwinding infrastructure
axt @ sym.imp.rust_begin_unwind
axt @ sym.imp._ZN4core9panicking5panic

# String recovery: Rust strings are (ptr, len) pairs, NOT null-terminated
# Look for: lea rdi, [str_ptr]; mov rsi, <length>

# Result/Option pattern: match on tag byte
# if (tag == 0) { /* None/Err */ } else { /* Some(val)/Ok(val) */ }
```

**Key Rust patterns to recognize:**
- `Result<T, E>` and `Option<T>` compile to tagged unions (discriminant + payload)
- Strings are `&str` = `(pointer, length)` — not null-terminated
- Closures become anonymous structs with captured variables as fields
- `Vec<T>` = `(pointer, length, capacity)` — three fields
- `Box<T>` = a heap pointer, `Drop` trait = destructor call
- Panics compile to calls to `core::panicking::panic` with file/line info
- Iterators and `.map()/.filter()` chains often inline completely

### Go Binaries

Go binaries are large, statically linked, and have unique calling conventions and runtime structures.

```bash
# Step 1: Recover symbols with GoReSym (even from stripped binaries)
GoReSym -d -p -t binary > symbols.json

# Step 2: Recover source structure with redress
redress -src binary              # Reconstruct source file/package tree
redress -type binary             # Dump all Go types
redress -interface binary        # Dump interface definitions
```

```
# Inside r2
# Go's PCLNTAB section contains function metadata
rabin2 -S binary | grep pclntab

# Go-specific sections
# .gopclntab  — function name table (goldmine)
# .gosymtab   — symbol table
# .go.buildid — build identifier
# .noptrdata  — non-pointer global data

# Go strings are (pointer, length) pairs like Rust
# Go calling convention: args/returns on stack (pre-1.17) or registers (1.17+)
# Goroutine creation: look for calls to runtime.newproc / runtime.newproc1
# Defer: runtime.deferproc / runtime.deferreturn
# Interface calls: runtime.assertI2I, runtime.convT2I
```

**Key Go patterns to recognize:**
- Functions return multiple values (return value + error)
- `runtime.morestack` at function entry = goroutine stack growth check
- `runtime.gopanic` / `runtime.gorecover` = panic/recover
- Channels: `runtime.makechan`, `runtime.chansend`, `runtime.chanrecv`
- Slices are `(pointer, length, capacity)` like Rust Vec
- Maps: `runtime.makemap`, `runtime.mapaccess1`, `runtime.mapassign`
- Interfaces are `(type_pointer, data_pointer)` — two words

### Dart/Flutter AOT Binaries

Flutter compiles Dart to native code via AOT snapshots (`libapp.so`). Custom binary format with no standard symbol tables.

```bash
# Step 1: Extract native libs from APK
apktool d app.apk -o extracted/
# Target: extracted/lib/arm64-v8a/libapp.so (and libflutter.so)

# Step 2: Recover symbols with blutter (primary tool)
python3 blutter.py extracted/lib/arm64-v8a/ output_dir/
# Output:
#   asm/       — Annotated assembly with Dart class/method names
#   objs.txt   — Object pool dump (strings, constants, closures)
#   pp.txt     — Object pool pointers
#   ida_script/ or r2_script/ — Import scripts for disassemblers
#   frida/     — Generated Frida hooks

# Step 3: Load symbols into r2
r2 extracted/lib/arm64-v8a/libapp.so
. output_dir/r2_script/r2.r2    # Load blutter symbols (if generated)

# Alternative: doldrums (version-specific snapshot parser)
# python3 doldrums.py <app_snapshot> <output>
```

**Key Dart/Flutter patterns to recognize:**
- Object pool: Dart stores constants, strings, and closures in a pool accessed via a dedicated register
- ARM64: Thread pointer in X26 (THR), object pool pointer in X27 (PP)
- No standard calling convention — Dart uses its own ABI
- Type guards: frequent `cid` (class ID) checks before method dispatch
- Null safety: `Null` checks compile to tag comparisons
- `libflutter.so` is the engine; `libapp.so` is your app code

### .NET NativeAOT Binaries

.NET NativeAOT strips IL and most metadata. Classical .NET tools (ILSpy, dnSpy) do NOT work.

```bash
# Step 1: Confirm it's NativeAOT (no IL metadata)
rabin2 -I binary    # Will show as native PE/ELF, NOT MSIL
rabin2 -z binary | grep -i "System\.\|S_P_CoreLib\|coreclr"

# Step 2: Use Ghidra with ghidra-nativeaot plugin
# Install: Copy ghidra-nativeaot to Ghidra Extensions folder
# The plugin recovers:
#   - MethodTable structures
#   - Type/class hierarchy fragments
#   - String literals
#   - Static field references

# Step 3: In r2 — treat as native binary with .NET pattern recognition
r2 -A binary

# .NET NativeAOT leaves breadcrumbs:
# - String literals in UTF-16LE with length prefix
# - MethodTable pointers at object+0x00
# - GC references follow specific patterns
# - S_P_CoreLib_ prefixed symbols = System.Private.CoreLib

# Search for .NET string patterns (length-prefixed UTF-16)
/x 00000000........0000    # Look for .NET string objects
```

**For standard .NET IL assemblies** (NOT NativeAOT), skip r2 entirely:

```bash
# ILSpy — full C# source recovery
ilspy binary.dll -o output/          # CLI decompile to C#
# Or use dotPeek / dnSpy GUI for interactive browsing
```

### Swift Binaries

Swift uses its own mangling scheme and metadata format.

```bash
# Demangle Swift symbols
swift-demangle < symbols.txt
echo '$s4MyApp10ViewModelC' | swift-demangle

# Inside r2
e bin.demangle = true    # r2 handles Swift demangling

# Swift-specific:
# - Protocol witness tables: functions with `witness` in demangled name
# - Value witnesses: copy, destroy, initializeBufferWithCopy operations
# - Type metadata: `$s...MN` (nominal type descriptor), `$s...Ma` (metadata accessor)
# - String interpolation: calls to _StringInterpolation methods
```

### Objective-C Binaries

Rich runtime metadata makes ObjC one of the easiest to reverse engineer.

```bash
# Extract class hierarchy (Mach-O only)
class-dump binary > classes.h

# Inside r2
rabin2 -c binary          # List all ObjC classes with methods
ic                        # List classes inside r2
icj                       # Classes as JSON
icc ClassName             # Show specific class methods
```

**Key ObjC patterns:**
- All method calls go through `objc_msgSend(receiver, selector, ...args)`
- Selectors are visible strings: `axt @ str.viewDidLoad:` finds all calls
- Categories add methods to existing classes at runtime

### Java/Android (APK/DEX)

For Dalvik/ART binaries, use dedicated tools before r2.

```bash
# Full APK → Java source
jadx app.apk -d output/

# Decode resources + smali
apktool d app.apk -o smali_output/

# For native JNI libraries inside APK:
# Extract lib/arm64-v8a/*.so and analyze with r2 as ELF
r2 -A lib/arm64-v8a/libnative.so
```

For native (JNI) code, combine r2 analysis with `jadx` output to understand the Java↔native boundary. Look for `JNI_OnLoad`, `Java_<package>_<class>_<method>` naming.

## Phase 6: Dynamic Analysis & Instrumentation

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

## Phase 7: Automation (r2pipe)

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
| Detect source language | `rabin2 -zz binary \| grep -iE "go\.build\|runtime\.\|_ZN\|core::\|_kDart\|System\.\|objc_msg\|swift_"` |
| Explain function with AI | `r2ai -d "Explain current function"` |
| AI-decompile with callees | `decai -dr` |
| Auto-solve crackme (AI) | `decai -a "solve this crackme"` |
| Find dangerous calls | `aaa; axt @ sym.imp.system` |
| Find buffer overflows (AI) | `decai -a "Find buffer overflows and propose a patch"` |
| Decompile main to C | `r2 -qc 'aaa; s main; pdg' binary` |
| Extract all strings | `rabin2 -zz binary` |
| Full binary triage | `rabin2 -I binary && rabin2 -z binary && rabin2 -i binary` |
| Diff two binaries | `radiff2 -c old.bin new.bin` |
| Demangle Rust symbols | `rabin2 -z binary \| rustfilt` |
| Recover Go symbols | `GoReSym -d -p -t binary > symbols.json` |
| Reconstruct Go types | `redress -type binary` |
| Flutter/Dart AOT symbols | `python3 blutter.py lib/arm64-v8a/ out/` |
| Decompile APK to Java | `jadx app.apk -d output/` |
| .NET IL → C# source | `ilspy binary.dll -o output/` |
| ObjC class dump | `class-dump binary > classes.h` |
| Demangle Swift symbols | `swift-demangle < symbols.txt` |
| Analyze C++ vtables | `av && avr` |
| Trace Java methods (Android) | `r2 frida://<pid>` then `\dt android.app.Activity` |
| Patch instruction to NOP | `wao nop` |
| Search for ROP gadgets | `/R` |
| Heap chunk analysis | `dmh` |
| List biggest functions | `afl~[2] \| sort -rn \| head` |

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
