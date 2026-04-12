# Threat Modeling Skill

Generate, review, and maintain threat models compatible with the [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) (.tm7 format). Designed as a [GitHub Copilot skill](https://code.visualstudio.com/docs/copilot/chat/chat-agent-mode#_custom-instructions) so AI agents can interact with threat models programmatically.

The AI skill uses an intermediate file format with [Markdown](https://daringfireball.net/projects/markdown/) + [Mermaid](https://github.com/mermaid-js/mermaid) for readability.

## Quick start

Install a VSCode extension like [bierner.markdown-mermaid](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) to preview Markdown with Mermaid diagrams.

Run a command:

```bash
cd .github/skills/threat-modeling
python tm7_cli.py <command> [options]
```

Example:

```bash
# Parse existing TM7 to editable Markdown+Mermaid
python tm7_cli.py parse --input model.tm7 --output model.md

# Generate TM7 from Markdown+Mermaid
python tm7_cli.py generate --input model.md --output model.tm7

# Quick summary of a TM7
python tm7_cli.py summary --input model.tm7
```

## Project layout

```
.github/skills/threat-modeling/
  tm7_cli.py          # CLI entry point
  references/         # TM7 format documentation
  tests/              # Unit tests
  SKILL.md            # Full reference — commands, options, format spec, examples
  _tmp/               # Scratch directory (git-ignored)
```

## Commands

| Command | Description |
|---------|-------------|
| `parse` | Parse a TM7 file to Markdown |
| `generate` | Generate a TM7 from Markdown |
| `summary` | Print a brief JSON summary of a TM7 file |
| `update-threats` | Update threat states/mitigations in a TM7 from Markdown |
| `validate` | Validate a Markdown threat model for completeness |

## Running tests

```bash
cd .github/skills/threat-modeling
python -m unittest discover -s tests -v
```

## Further reading

See [SKILL.md](.github/skills/threat-modeling/SKILL.md) for the full command reference, examples, and gotchas.
