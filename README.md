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
tools/
  tm7_validate.cs     # C# harness — validates TM7 via TMT's own deserializer
  tm7_validate.csproj  # .NET project file (targets net48 / x86)
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

## Validating TM7 files with TMT's deserializer

`tools/tm7_validate.exe` uses Microsoft Threat Modeling Tool's own `DataContractSerializer` types to validate that a `.tm7` file can be deserialized — the same check TMT performs when opening a file.

### Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) (any recent version that supports `net48` targeting)
- Windows with .NET Framework 4.8 (ships with Windows 10/11)
- [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool) installed (ClickOnce)

### Building

```cmd
cd tools
dotnet build -c Release
```

### Usage

The tool auto-discovers the TMT ClickOnce install under `%LOCALAPPDATA%\Apps\2.0`.

```cmd
dotnet run --project tools -c Release -- file1.tm7 [file2.tm7 ...]
```

Or run the compiled exe directly:

```cmd
tools\bin\Release\net48\tm7_validate.exe file1.tm7 [file2.tm7 ...]
```

To override the auto-discovered path, set `TMT_DIR`:

```cmd
set TMT_DIR=C:\Users\you\AppData\Local\Apps\2.0\...\tmt7..tion_...
```

For each file the tool prints `OK` or `FAILED` with the deserialization error details. Exit code is the number of failures (0 = all passed).

## Further reading

See [SKILL.md](.github/skills/threat-modeling/SKILL.md) for the full command reference, examples, and gotchas.

## References

Sample data:
- https://github.com/matthiasrohr/OTMT
  - [Simple Threat Model_https.tm7](https://github.com/matthiasrohr/OTMT/blob/master/Simple%20Threat%20Model_https.tm7)
  - [Complex Threat Model_with_security_gateway.tm7](https://github.com/matthiasrohr/OTMT/blob/master/Complex%20Threat%20Model_with_security_gateway.tm7)
- [Azure VM Bicep](https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.compute/vm-simple-windows/main.bicep)