# Copilot Skills

A collection of agent skills for GitHub Copilot CLI and Claude.

## Installation

### As a Plugin Marketplace (Copilot CLI)

Add this repository as a plugin marketplace in Copilot CLI:

```
/plugin marketplace add https://github.com/<owner>/copilot-skills
```

Then install skills:

```
/plugin install reverse-engineer
```

### As Personal Skills (manual)

Copy any skill folder into your personal skills directory:

```bash
# For Copilot CLI
cp -r skills/reverse-engineer ~/.copilot/skills/reverse-engineer

# For Claude
cp -r skills/reverse-engineer ~/.claude/skills/reverse-engineer
```

### As Project Skills

Copy into your repository's `.github/skills` directory:

```bash
cp -r skills/reverse-engineer /path/to/repo/.github/skills/reverse-engineer
```

## Available Skills

| Skill | Description |
|-------|-------------|
| [reverse-engineer](skills/reverse-engineer/) | Reverse engineer native binaries (ELF, PE, Mach-O) into readable C using radare2, Ghidra, and companion tools. Covers triage, disassembly, decompilation, and C source reconstruction. |

## Creating New Skills

Each skill lives in its own directory under `skills/` and must contain a `SKILL.md` file with YAML frontmatter (`name` and `description`) and a Markdown body with instructions.

```
skills/
└── my-skill/
    ├── SKILL.md          # Required — instructions and metadata
    ├── scripts/          # Optional — executable helpers
    ├── references/       # Optional — reference docs loaded on demand
    └── assets/           # Optional — templates, images, etc.
```

## License

MIT
