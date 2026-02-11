---
name: reverse-engineer
description: Reverse engineer native binaries (ELF, PE, Mach-O) into readable C source code using radare2, Ghidra, and companion tools. Use when the user asks to disassemble, decompile, analyze, or reverse engineer a binary, executable, shared library, firmware image, or object file. Also use when asked to find vulnerabilities in binaries, solve crackmes/CTFs, extract strings or symbols, understand unknown executables, reconstruct C source from machine code, or perform binary diffing. Triggers on mentions of radare2, r2, Ghidra, disassembly, decompilation, binary analysis, reverse engineering, RE, or malware analysis.
---

# Binary Reverse Engineering to C

Reverse engineer native binaries into readable C using a structured pipeline: **triage → disassembly → decompilation → reconstruction**.

## Tool Stack

| Tool | Purpose | Install |
|------|---------|---------|
| `r2` | Interactive disassembly, analysis, debugging | `brew install radare2` / `apt install radare2` |
| `rabin2` | Static binary metadata (headers, imports, strings, sections) | Bundled with r2 |
| `rasm2` | Assemble/disassemble individual instructions | Bundled with r2 |
| `radiff2` | Binary diffing | Bundled with r2 |
| `rahash2` | Hashing and checksums | Bundled with r2 |
| `r2ghidra` | Ghidra decompiler as r2 plugin | `r2pm -ci r2ghidra` |
| `r2dec` | Lightweight r2 decompiler | `r2pm -ci r2dec` |
| `decai` | AI-assisted decompilation | `r2pm -ci decai` |
| `retdec` | RetDec decompiler plugin | `r2pm -ci retdec` |

Verify installation:

```bash
r2 -v && rabin2 -v
r2 -qc 'e asm.arch' --    # check default arch
```

## Phase 1: Triage — Identify the Target

Before disassembly, extract all metadata to understand what you're working with.

```bash
# File type, arch, bits, endianness, OS, compiler, security features
rabin2 -I <binary>

# Entry point(s)
rabin2 -e <binary>

# Sections (code vs data, permissions, sizes)
rabin2 -S <binary>

# Imports (external API calls — reveals behavior)
rabin2 -i <binary>

# Exports (public symbols)
rabin2 -E <binary>

# Linked libraries
rabin2 -l <binary>

# Strings in data sections (passwords, URLs, keys, format strings, error messages)
rabin2 -z <binary>

# ALL strings including raw binary (catches obfuscated/encrypted strings)
rabin2 -zz <binary>

# Headers
rabin2 -H <binary>

# Relocations
rabin2 -R <binary>

# Classes (C++/ObjC/Java/Dalvik)
rabin2 -c <binary>

# Debug/DWARF info (if present — massively simplifies RE)
rabin2 -d <binary>

# Everything at once (verbose)
rabin2 -g <binary>

# Hash the binary for identification
rahash2 -a md5,sha256 <binary>
```

**Key triage questions to answer:**
1. Architecture? (x86, x86_64, ARM, MIPS, PPC, etc.)
2. Stripped or has symbols?
3. Statically or dynamically linked?
4. What does it import? (network? file? crypto? process?)
5. Interesting strings? (hardcoded creds, URLs, error messages)
6. Any anti-debug? (`ptrace`, `IsDebuggerPresent`)
7. Packed/obfuscated? (high entropy sections, UPX, custom packers)

## Phase 2: Disassembly — Understand the Machine Code

### Open and Analyze

```bash
# Open binary in r2 (read-only by default)
r2 <binary>

# Open with write mode (for patching)
r2 -w <binary>

# Open and auto-analyze
r2 -A <binary>        # equivalent to r2 then `aa`
r2 -AA <binary>       # deeper analysis (aaa)
```

### Analysis Commands (inside r2 shell)

Run analysis before doing anything else:

```
aa          # Analyze all symbols and entry points (fast, minimum)
aaa         # Analyze all — includes aa + type propagation + more (recommended)
aab         # Basic block analysis (Nucleus algorithm — good for stripped bins)
aac         # Analyze function calls
aaf         # Analyze all function calls
aar         # Analyze data references
aad         # Analyze pointer-to-pointer references
aaaa        # Experimental deep analysis (slow but thorough)
afl         # List all discovered functions
aflj        # List functions as JSON
afl=        # ASCII-art bar chart of function ranges
afn <name> [addr]  # Rename function
afvn <old> <new>   # Rename local variable
```

### Navigate and Disassemble

```
s main            # Seek to main (or sym.main)
s <addr>          # Seek to address
s- / s+           # Undo/redo seek

pdf               # Print disassembly of current function
pdf @ main        # Print disassembly of main
pd 20             # Print 20 instructions from current position
pd 20 @ 0x401000  # Print 20 instructions at address
pdr               # Print disassembly of function recursively (follow calls)
pds               # Print function summary (calls + strings only)
pdsf              # Summary of current function
pdc               # Pseudo-decompiler (all architectures)

# Cross-references (critical for understanding control flow)
axt [addr]        # Find xrefs TO this address (who calls/references this?)
axf [addr]        # Find xrefs FROM this address (what does this call/reference?)
axtg              # Generate xref graph commands
axg [addr]        # Show xref graph to reach an address

# Information about current function
afi               # Function info (size, complexity, calls, xrefs)
afb               # List basic blocks of current function
afCc              # Cyclomatic complexity
```

### Visual Mode

```
V                 # Enter visual mode
VV                # Enter graph mode (control flow graph)
p / P             # Rotate view modes (hex, disasm, debug)
v                 # Code analysis menu (function browser)
:                 # Enter r2 command from visual mode
q                 # Exit visual mode
hjkl              # Navigate (vim-style)
x                 # Show xrefs
```

### Searching

```
/ <string>        # Search for string
/x <hex>          # Search for hex bytes
/c <asm>          # Search for assembly instruction pattern
/R                # Search for ROP gadgets
/a <asm>          # Assemble instruction and search for its bytes
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

## Phase 3: Decompilation — Lift to C

Use decompiler plugins to convert disassembly to C pseudocode.

### Built-in Pseudo-Decompiler (pdc)

Available for ALL architectures with no plugins needed:

```
pdc               # Pseudo-decompile current function
pdc @ main        # Pseudo-decompile main
```

Output is verbose but useful as a starting point and fast.

### r2ghidra (pdg) — Recommended

Install: `r2pm -ci r2ghidra`

```
pdg               # Decompile current function to C
pdg @ main        # Decompile main
pdgo              # Decompile with offset annotations (map C lines → addresses)
pdga              # Side-by-side: disassembly | decompilation
pdgj              # Decompile as JSON (for scripting/automation)
pdgsd             # Decompile and show debug info
```

Configure r2ghidra:

```
e r2ghidra.casts=true       # Show type casts
e r2ghidra.lang=x86:LE:64:default  # Override arch detection
e r2ghidra.roprop=2         # Read-only constant propagation level (0-4)
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

Configure r2dec:

```
e r2dec.casts=true          # Show type casts
e r2dec.asm=true            # Show pseudo next to assembly
e r2dec.xrefs=true          # Show xrefs in output
```

### Decompile All Functions (scripting)

```bash
# Decompile every function to a file
r2 -q -c 'aaa; afl~[0] | while read addr; do echo "// --- $addr ---"; pdg @ $addr; done' binary > decompiled.c

# Or via r2pipe one-liner
r2 -qc 'aaa; afl~[0]' binary | while read fn; do
  r2 -qc "aaa; s $fn; pdg" binary
done > full_decompiled.c
```

## Phase 4: Reconstruction — From Pseudocode to Real C

The decompiler output is pseudocode, not compilable C. Transform it:

### Reconstruction Checklist

1. **Map imports to headers**: `#include <stdio.h>`, `<stdlib.h>`, `<string.h>`, etc.
2. **Recover types**: Replace `int64_t param_1` with meaningful types (`char *filename`, `struct foo *ctx`)
3. **Name variables**: Use context clues (strings, API calls, comparisons) to name locals
4. **Name functions**: Use call patterns, strings, error messages to name `fcn.0040xxxx`
5. **Reconstruct structs**: Field access patterns (`*(param_1 + 0x8)`) → struct definitions
6. **Recover enums/constants**: Magic numbers → named constants (`0x7f454c46` → `ELF_MAGIC`)
7. **Simplify control flow**: Flatten goto-heavy decompiler output into if/else, for, while, switch
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

Use r2 type commands to define and apply structs:

```
# Define types in r2
tk my_struct=struct
ts my_struct 0 field_0 uint64_t
ts my_struct 8 field_8 uint64_t

# Or load from a C header
to header.h

# Apply type to a function argument
afsr <function> <new_signature>
```

## Phase 5: Advanced Techniques

### Debugging (Dynamic Analysis)

```bash
r2 -d <binary>           # Open in debugger mode
r2 -d -A <binary>        # Debug + auto-analyze
```

Inside debugger:

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

### Emulation (ESIL)

Run code without executing natively — safe for malware:

```
aei               # Initialize ESIL VM
aeim              # Initialize ESIL memory/stack
aeip              # Set instruction pointer to entry
aes               # Step one instruction
aeso              # Step over
aer               # Show ESIL registers
```

### Binary Patching

```bash
r2 -w <binary>           # Open in write mode
```

```
wa nop @ 0x401234        # Write NOP at address
"wa jmp 0x40abcd" @ addr # Write jump instruction
wx 9090 @ 0x401234       # Write raw hex bytes
wao nop @ addr           # Write NOP opcode over current instruction
```

### Binary Diffing

```bash
radiff2 binary_v1 binary_v2           # Basic diff
radiff2 -c binary_v1 binary_v2        # Code diffing
radiff2 -g main binary_v1 binary_v2   # Graph diff of main function
```

### Scripting with r2pipe

```python
import r2pipe

r2 = r2pipe.open("/path/to/binary")
r2.cmd("aaa")

# List all functions
functions = r2.cmdj("aflj")
for fn in functions:
    print(f"{fn['name']} at {fn['offset']:#x}, size={fn['size']}")

# Decompile a function
r2.cmd("s main")
c_code = r2.cmd("pdg")
print(c_code)

r2.quit()
```

## Quick Reference — Common Workflows

### "What does this binary do?"

```bash
rabin2 -I binary && rabin2 -z binary && rabin2 -i binary
r2 -qc 'aaa; afl; pds @ main' binary
```

### "Decompile main to C"

```bash
r2 -qc 'aaa; s main; pdg' binary
```

### "Find all calls to a dangerous function"

```bash
r2 -qc 'aaa; axt @ sym.imp.strcpy' binary
r2 -qc 'aaa; axt @ sym.imp.gets' binary
r2 -qc 'aaa; axt @ sym.imp.system' binary
```

### "Extract and list all hardcoded strings"

```bash
rabin2 -z binary           # data section strings
rabin2 -zz binary          # all strings including raw
r2 -qc 'aaa; izz' binary  # from inside r2
```

### "Solve a crackme"

```bash
r2 -A binary
# 1. Find main: afl~main
# 2. Disassemble: pdf @ main
# 3. Find comparison: look for cmp/test before conditional jumps
# 4. Trace the compared value back through the code
# 5. Patch the jump: wa jmp <success_addr> @ <cmp_addr>
# Or: extract the comparison constant from the disassembly
```

### "Diff two binary versions"

```bash
radiff2 -c old_binary new_binary
r2 -qc 'aaa; afl' old_binary > old_fns.txt
r2 -qc 'aaa; afl' new_binary > new_fns.txt
diff old_fns.txt new_fns.txt
```

## r2 Self-Documentation

r2 is fully self-documenting. When uncertain about any command:

```
?              # Top-level help (all command families)
a?             # Help for analysis commands
p?             # Help for print commands
pd?            # Help for print disassembly subcommands
af?            # Help for analyze function commands
e??anal.       # List all analysis configuration variables
e??r2ghidra.   # List all r2ghidra configuration variables
```

Append `?` to any command prefix to explore its subcommands.

## Safety Notes

- **Always work on copies** — never reverse engineer original files directly
- **Use VMs** for unknown/malicious binaries — they may contain malware
- **Snapshot VMs** before dynamic analysis
- **Use ESIL emulation** when you cannot safely execute the binary
- **Respect legal boundaries** — only reverse engineer binaries you have legal rights to analyze
