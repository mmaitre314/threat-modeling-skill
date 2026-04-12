---
name: threat-modeling
description: "Create, update, and review threat models using Microsoft Threat Modeling Tool TM7 format. Use for: generating threat models from code repos, STRIDE analysis, editing threats, converting between Markdown/Mermaid and TM7, security review workflows."
---

# Threat Modeling Skill

Generate, review, and maintain threat models compatible with the Microsoft Threat Modeling Tool (.tm7 format). Supports a human-friendly Markdown+Mermaid intermediate format for editing and review, with round-tripping to/from TM7 XML.

## Overview

The Microsoft Threat Modeling Tool uses the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to identify threats against a data-flow diagram. TM7 files are large XML documents that embed:

- **Drawing surfaces** — visual DFD elements (processes, data stores, external interactors, trust boundaries)
- **Data flows** — connections between elements with security properties
- **Threat instances** — STRIDE threats generated or manually added, with state/priority/mitigations
- **Knowledge base** — element type definitions and threat generation rules

Because TM7 XML is verbose and not human-editable, this skill uses a **Markdown threat model** as the primary authoring format. The CLI can convert between formats.

## Workflow

### 1. Generate a threat model from a code repository

Analyze the repo structure, identify components, and create a Markdown threat model:

1. Explore the codebase to identify: services/processes, data stores, external dependencies, trust boundaries, data flows, authentication mechanisms
2. Create a Markdown threat model file (see format below)
3. Convert to TM7 using the CLI

### 2. Review and iterate with user feedback

The Markdown format lets users easily:
- Add/remove/rename elements
- Update threat status (Mitigated, Not Applicable, Needs Investigation)
- Add justifications and mitigations
- Adjust priority and risk ratings

### 3. Export to TM7

Convert the reviewed Markdown back to TM7 for use with the Microsoft Threat Modeling Tool.

## Usage

All commands below assume you are in the skill directory (the folder containing `tm7_cli.py`).

```bash
python tm7_cli.py <command> [options]
```

Use `--help` on any subcommand for details.

### Commands

| Command | Description | Key Options |
|---------|-------------|-------------|
| `parse` | Parse a TM7 file to Markdown | `--input <tm7>`, `--output <md>` |
| `generate` | Generate a TM7 from Markdown | `--input <md>`, `--output <tm7>`, `--template <tm7>` |
| `summary` | Print a brief JSON summary of a TM7 file | `--input <tm7>`, `--output-file <json>` |
| `update-threats` | Update threat states/mitigations in a TM7 from Markdown | `--tm7 <tm7>`, `--markdown <md>`, `--output <tm7>` |
| `validate` | Validate a Markdown threat model for completeness | `--input <md>` |

### Examples

```bash
# Parse existing TM7 to editable Markdown
python tm7_cli.py parse --input model.tm7 --output model.md

# Generate TM7 from Markdown (optionally using existing TM7 as template for KB)
python tm7_cli.py generate --input model.md --output model.tm7
python tm7_cli.py generate --input model.md --output model.tm7 --template existing.tm7

# Quick summary of a TM7
python tm7_cli.py summary --input model.tm7

# Update just the threat states from reviewed Markdown back into existing TM7
python tm7_cli.py update-threats --tm7 model.tm7 --markdown reviewed.md --output updated.tm7

# Validate Markdown threat model for missing fields
python tm7_cli.py validate --input model.md
```

## Markdown Threat Model Format

The Markdown format is the **primary authoring surface**. It uses a structured Markdown document with a Mermaid data-flow diagram and tables for threats.

````markdown
# Threat Model: [System Name]

## Metadata
- **Owner:** [name]
- **Reviewer:** [name]
- **Date:** [YYYY-MM-DD]
- **Description:** [High-level system description]
- **Assumptions:** [Key assumptions]
- **External Dependencies:** [External dependencies]

## Data Flow Diagram

```mermaid
graph LR
    subgraph "Trust Boundary: Internet"
        User["User (External Interactor)"]
    end

    subgraph "Trust Boundary: Corporate Network"
        WebApp[["Web Application (Process)"]]
        API[["API Server (Process)"]]
        DB[("SQL Database (Data Store)")]
    end

    User -->|"HTTPS Request"| WebApp
    WebApp -->|"REST API Call"| API
    API -->|"SQL Query"| DB
```

## Elements

| Name | Type | Generic Type | Notes |
|------|------|-------------|-------|
| User | External Interactor | GE.EI | End user accessing via browser |
| Web Application | Process | GE.P | ASP.NET web frontend |
| API Server | Process | GE.P | REST API backend |
| SQL Database | Data Store | GE.DS | Azure SQL Database |

## Data Flows

| Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |
|------|--------|--------|----------|---------------------|-------------------------|-------------------|
| HTTPS Request | User | Web Application | HTTPS | Yes | Yes | Yes |
| REST API Call | Web Application | API Server | HTTPS | Yes | Yes | Yes |
| SQL Query | API Server | SQL Database | SQL | Yes | No | No |

## Trust Boundaries

| Name | Elements |
|------|----------|
| Internet | User |
| Corporate Network | Web Application, API Server, SQL Database |

## Threats

### T1: SQL Injection on SQL Database
- **Category:** Tampering
- **State:** Needs Investigation
- **Priority:** High
- **Risk:** High
- **Description:** SQL injection is an attack in which malicious code is inserted into strings that are later passed to an instance of SQL Server for parsing and execution.
- **Target:** SQL Database
- **Source:** API Server
- **Flow:** SQL Query
- **Mitigation:** Use parameterized queries via ORM (Entity Framework / Hibernate)
- **Justification:**

### T2: Cross-Site Scripting (XSS)
- **Category:** Tampering
- **State:** Mitigated
- **Priority:** Medium
- **Risk:** Medium
- **Description:** The web server could be subject to XSS because it does not sanitize untrusted input.
- **Target:** Web Application
- **Source:** User
- **Flow:** HTTPS Request
- **Mitigation:** Output encoding enabled via framework defaults
- **Justification:** ASP.NET Razor auto-encodes all output by default
````

### Element Type Reference

| Generic Type | Code | Mermaid Shape | Description |
|-------------|------|---------------|-------------|
| External Interactor | `GE.EI` | `["name"]` | External entity outside your control |
| Process | `GE.P` | `[["name"]]` | Software process / service |
| Data Store | `GE.DS` | `[("name")]` | Database, file system, cache |
| Data Flow | `GE.DF` | `-->` arrow | Data movement between elements |
| Trust Boundary | `GE.TB` | `subgraph` | Security boundary |

### STRIDE Categories

| Code | Category | Question |
|------|----------|----------|
| S | Spoofing | Can an attacker pretend to be something/someone else? |
| T | Tampering | Can an attacker modify data? |
| R | Repudiation | Can an attacker deny performing an action? |
| I | Information Disclosure | Can an attacker read data they shouldn't? |
| D | Denial of Service | Can an attacker crash or degrade the system? |
| E | Elevation of Privilege | Can an attacker gain unauthorized access? |

### Threat States

| State | Description |
|-------|-------------|
| `Needs Investigation` | Not yet reviewed |
| `Not Applicable` | Threat does not apply (provide justification) |
| `Mitigated` | Mitigation is in place (describe it) |
| `Not Started` | Acknowledged but not yet addressed |
| `Auto Generated` | Auto-generated by the tool, pending review |

## Generating a Threat Model from a Code Repository

When analyzing a repository, follow this process:

1. **Identify components**: Look for services, APIs, web apps, databases, message queues, caches, external integrations
2. **Map data flows**: Trace how data moves between components (HTTP, gRPC, SQL, message bus, file I/O)
3. **Identify trust boundaries**: Network segments, cloud/on-prem, internal/external, privileged/unprivileged
4. **Apply STRIDE per element**: For each element, consider which STRIDE categories apply
5. **Write the Markdown threat model** using the format above
6. **Convert to TM7** using: `python tm7_cli.py generate --input model.md --output model.tm7`

### Tips

- Focus on the most security-critical flows first
- External Interactors crossing trust boundaries generate the most threats
- Data flows crossing trust boundaries need confidentiality and integrity analysis
- Data stores holding credentials or PII need special attention
- Prefer specific TypeIds (e.g., `SE.P.TMCore.WebApp`) over generic ones when the component type is known

## Scratch Directory

The `_tmp/` folder inside the skill directory is checked in but its contents are git-ignored.
Use it for generated files and any other transient data.
