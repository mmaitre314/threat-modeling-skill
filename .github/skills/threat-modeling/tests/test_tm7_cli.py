"""Unit tests for the threat-modeling skill (tm7_cli.py)."""

from __future__ import annotations

import textwrap
import uuid
from pathlib import Path

import pytest

# Make imports work when running from this directory or the skill root.
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tm7_cli import (
    DataFlow,
    Element,
    MarkdownGenerator,
    MarkdownParser,
    STATE_MAP,
    STATE_MAP_REVERSE,
    STRIDE_CATEGORIES,
    STRIDE_REVERSE,
    TM7Generator,
    TM7Parser,
    Threat,
    ThreatModel,
    ThreatModelMeta,
    TrustBoundary,
    generate_summary,
    validate_markdown,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_TM7_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "tmp" / "tm7"

SIMPLE_TM7 = SAMPLE_TM7_DIR / "Simple Threat Model_https.tm7"
COMPLEX_TM7 = SAMPLE_TM7_DIR / "Complex Threat Model_with_security_gateway.tm7"
AZ_TM7 = SAMPLE_TM7_DIR / "az-security-threat-model.tm7"


def _has_sample(path: Path) -> bool:
    return path.exists()


SAMPLE_MD = textwrap.dedent("""\
    # Threat Model: Test System

    ## Metadata
    - **Owner:** Alice
    - **Reviewer:** Bob
    - **Date:** 2026-01-15
    - **Description:** A test system
    - **Assumptions:** None
    - **External Dependencies:** None

    ## Data Flow Diagram

    ```mermaid
    graph LR
        User["User (External Interactor)"]
        WebApp[["Web App (Process)"]]
        DB[("Database (Data Store)")]
        User -->|"HTTPS"| WebApp
        WebApp -->|"SQL"| DB
    ```

    ## Elements

    | Name | Type | Generic Type | Notes |
    |------|------|-------------|-------|
    | User | External Interactor | GE.EI | End user |
    | Web App | Process | GE.P | Frontend |
    | Database | Data Store | GE.DS | PostgreSQL |

    ## Data Flows

    | Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |
    |------|--------|--------|----------|---------------------|-------------------------|-------------------|
    | HTTPS | User | Web App | HTTPS | Yes | Yes | Yes |
    | SQL | Web App | Database | SQL | Yes | No | No |

    ## Trust Boundaries

    | Name | Elements |
    |------|----------|
    | Internet | User |
    | DMZ | Web App, Database |

    ## Threats

    ### T1: SQL Injection
    - **Category:** Tampering
    - **State:** Needs Investigation
    - **Priority:** High
    - **Risk:** High
    - **Description:** SQL injection on Database
    - **Target:** Database
    - **Source:** Web App
    - **Flow:** SQL
    - **Mitigation:** Use parameterized queries
    - **Justification:**

    ### T2: XSS
    - **Category:** Tampering
    - **State:** Mitigated
    - **Priority:** Medium
    - **Risk:** Medium
    - **Description:** Cross-site scripting
    - **Target:** Web App
    - **Source:** User
    - **Flow:** HTTPS
    - **Mitigation:** Output encoding
    - **Justification:** Framework auto-encodes

    ### T3: Spoofing User
    - **Category:** Spoofing
    - **State:** Not Applicable
    - **Priority:** Low
    - **Risk:** Low
    - **Description:** User spoofing
    - **Target:** Web App
    - **Source:** User
    - **Flow:** HTTPS
    - **Mitigation:**
    - **Justification:** Users are authenticated via SSO
""")


@pytest.fixture
def sample_md(tmp_path: Path) -> Path:
    p = tmp_path / "model.md"
    p.write_text(SAMPLE_MD, encoding="utf-8")
    return p


@pytest.fixture
def sample_model() -> ThreatModel:
    """Build a ThreatModel in-memory for generator tests."""
    model = ThreatModel()
    model.meta = ThreatModelMeta(
        name="Test System",
        owner="Alice",
        reviewer="Bob",
        description="A test system",
    )
    u = Element(name="User", guid=str(uuid.uuid4()), generic_type="GE.EI")
    w = Element(name="Web App", guid=str(uuid.uuid4()), generic_type="GE.P")
    d = Element(name="Database", guid=str(uuid.uuid4()), generic_type="GE.DS")
    model.elements = [u, w, d]
    model.flows = [
        DataFlow(name="HTTPS", guid=str(uuid.uuid4()), source_guid=u.guid, target_guid=w.guid),
        DataFlow(name="SQL", guid=str(uuid.uuid4()), source_guid=w.guid, target_guid=d.guid),
    ]
    model.boundaries = [
        TrustBoundary(name="Internet", guid=str(uuid.uuid4()), elements=["User"]),
        TrustBoundary(name="DMZ", guid=str(uuid.uuid4()), elements=["Web App", "Database"]),
    ]
    model.threats = [
        Threat(id="1", title="SQL Injection", category="Tampering", state="Needs Investigation",
               priority="High", risk="High", description="SQL injection on DB",
               source="Web App", target="Database", flow="SQL", mitigation="Use ORM"),
        Threat(id="2", title="XSS", category="Tampering", state="Mitigated",
               priority="Medium", risk="Medium", description="Cross-site scripting",
               source="User", target="Web App", flow="HTTPS", mitigation="Output encoding"),
    ]
    return model


# ===================================================================
# Markdown Parser Tests
# ===================================================================


class TestMarkdownParser:
    def test_parse_meta(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        assert model.meta.name == "Test System"
        assert model.meta.owner == "Alice"
        assert model.meta.reviewer == "Bob"
        assert model.meta.date == "2026-01-15"
        assert model.meta.description == "A test system"

    def test_parse_elements(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        assert len(model.elements) == 3
        names = {e.name for e in model.elements}
        assert names == {"User", "Web App", "Database"}
        types = {e.name: e.generic_type for e in model.elements}
        assert types["User"] == "GE.EI"
        assert types["Web App"] == "GE.P"
        assert types["Database"] == "GE.DS"

    def test_elements_have_guids(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        for el in model.elements:
            uuid.UUID(el.guid)  # should not raise

    def test_parse_flows(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        assert len(model.flows) == 2
        flow_names = {f.name for f in model.flows}
        assert flow_names == {"HTTPS", "SQL"}

    def test_flow_sources_and_targets(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        https = next(f for f in model.flows if f.name == "HTTPS")
        assert https.source_guid == "User"
        assert https.target_guid == "Web App"
        assert https.authenticates_source == "Yes"
        assert https.provides_confidentiality == "Yes"

    def test_parse_boundaries(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        assert len(model.boundaries) == 2
        names = {tb.name for tb in model.boundaries}
        assert names == {"Internet", "DMZ"}
        dmz = next(tb for tb in model.boundaries if tb.name == "DMZ")
        assert set(dmz.elements) == {"Web App", "Database"}

    def test_parse_threats(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        assert len(model.threats) == 3

    def test_threat_fields(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        t1 = next(t for t in model.threats if t.title == "SQL Injection")
        assert t1.id == "1"
        assert t1.category == "Tampering"
        assert t1.state == "Needs Investigation"
        assert t1.priority == "High"
        assert t1.risk == "High"
        assert t1.target == "Database"
        assert t1.source == "Web App"
        assert t1.flow == "SQL"
        assert t1.mitigation == "Use parameterized queries"

    def test_threat_states(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        states = {t.title: t.state for t in model.threats}
        assert states["SQL Injection"] == "Needs Investigation"
        assert states["XSS"] == "Mitigated"
        assert states["Spoofing User"] == "Not Applicable"

    def test_threat_justification(self, sample_md: Path):
        model = MarkdownParser(sample_md).parse()
        t3 = next(t for t in model.threats if t.title == "Spoofing User")
        assert t3.justification == "Users are authenticated via SSO"

    def test_numeric_id_without_T_prefix(self, tmp_path: Path):
        md = textwrap.dedent("""\
            # Threat Model: X

            ## Threats

            ### 42: Some Threat
            - **Category:** Spoofing
            - **State:** Mitigated
            - **Priority:** High
        """)
        p = tmp_path / "bare_id.md"
        p.write_text(md, encoding="utf-8")
        model = MarkdownParser(p).parse()
        assert model.threats[0].id == "42"
        assert model.threats[0].title == "Some Threat"

    def test_empty_sections(self, tmp_path: Path):
        md = "# Threat Model: Empty\n\n## Metadata\n- **Owner:** Me\n"
        p = tmp_path / "empty.md"
        p.write_text(md, encoding="utf-8")
        model = MarkdownParser(p).parse()
        assert model.meta.name == "Empty"
        assert model.elements == []
        assert model.flows == []
        assert model.threats == []


# ===================================================================
# Markdown Generator Tests
# ===================================================================


class TestMarkdownGenerator:
    def test_generates_title(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "# Threat Model: Test System" in md

    def test_generates_metadata(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "**Owner:** Alice" in md
        assert "**Reviewer:** Bob" in md

    def test_generates_elements_table(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "| User | External Interactor | GE.EI |" in md
        assert "| Web App | Process | GE.P |" in md
        assert "| Database | Data Store | GE.DS |" in md

    def test_generates_flows_table(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "## Data Flows" in md
        assert "| HTTPS |" in md
        assert "| SQL |" in md

    def test_generates_boundaries(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "## Trust Boundaries" in md
        assert "| Internet | User |" in md
        assert "| DMZ | Web App, Database |" in md

    def test_generates_mermaid_diagram(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "```mermaid" in md
        assert "graph LR" in md

    def test_mermaid_has_subgraphs(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert 'subgraph "Internet"' in md
        assert 'subgraph "DMZ"' in md

    def test_mermaid_element_shapes(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "(External Interactor)" in md
        assert "(Process)" in md
        assert "(Data Store)" in md

    def test_generates_threats(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "### 1: SQL Injection" in md
        assert "### 2: XSS" in md
        assert "- **Category:** Tampering" in md
        assert "- **State:** Needs Investigation" in md
        assert "- **State:** Mitigated" in md

    def test_no_boundaries_section_when_empty(self):
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="No Boundaries")
        md = MarkdownGenerator().generate(model)
        assert "## Trust Boundaries" not in md


# ===================================================================
# Markdown Round-Trip Tests
# ===================================================================


class TestMarkdownRoundTrip:
    def test_metadata_survives(self, sample_md: Path, tmp_path: Path):
        model = MarkdownParser(sample_md).parse()
        md = MarkdownGenerator().generate(model)
        p2 = tmp_path / "rt.md"
        p2.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p2).parse()
        assert model2.meta.name == model.meta.name
        assert model2.meta.owner == model.meta.owner

    def test_elements_survive(self, sample_md: Path, tmp_path: Path):
        model = MarkdownParser(sample_md).parse()
        md = MarkdownGenerator().generate(model)
        p2 = tmp_path / "rt.md"
        p2.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p2).parse()
        assert len(model2.elements) == len(model.elements)
        assert {e.name for e in model2.elements} == {e.name for e in model.elements}

    def test_threat_states_survive(self, sample_md: Path, tmp_path: Path):
        model = MarkdownParser(sample_md).parse()
        md = MarkdownGenerator().generate(model)
        p2 = tmp_path / "rt.md"
        p2.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p2).parse()
        states1 = {t.title: t.state for t in model.threats}
        states2 = {t.title: t.state for t in model2.threats}
        assert states1 == states2

    def test_threat_categories_survive(self, sample_md: Path, tmp_path: Path):
        model = MarkdownParser(sample_md).parse()
        md = MarkdownGenerator().generate(model)
        p2 = tmp_path / "rt.md"
        p2.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p2).parse()
        cats1 = {t.title: t.category for t in model.threats}
        cats2 = {t.title: t.category for t in model2.threats}
        assert cats1 == cats2

    def test_threat_ids_survive(self, sample_md: Path, tmp_path: Path):
        model = MarkdownParser(sample_md).parse()
        md = MarkdownGenerator().generate(model)
        p2 = tmp_path / "rt.md"
        p2.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p2).parse()
        ids1 = {t.title: t.id for t in model.threats}
        ids2 = {t.title: t.id for t in model2.threats}
        assert ids1 == ids2


# ===================================================================
# TM7 Generator Tests
# ===================================================================


class TestTM7Generator:
    def test_generates_valid_xml(self, sample_model: ThreatModel, tmp_path: Path):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        out = tmp_path / "out.tm7"
        tree.write(str(out), encoding="unicode", xml_declaration=True)
        assert out.exists()
        assert out.stat().st_size > 100

    def test_xml_has_meta(self, sample_model: ThreatModel, tmp_path: Path):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        out = tmp_path / "out.tm7"
        tree.write(str(out), encoding="unicode", xml_declaration=True)
        text = out.read_text(encoding="utf-8")
        assert "Test System" in text
        assert "Alice" in text

    def test_xml_has_elements(self, sample_model: ThreatModel, tmp_path: Path):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        out = tmp_path / "out.tm7"
        tree.write(str(out), encoding="unicode", xml_declaration=True)
        # Re-parse with our own parser
        model2 = TM7Parser(out).parse()
        assert len(model2.elements) >= 3
        names = {e.name for e in model2.elements}
        assert "User" in names
        assert "Web App" in names
        assert "Database" in names

    def test_xml_has_threats(self, sample_model: ThreatModel, tmp_path: Path):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        out = tmp_path / "out.tm7"
        tree.write(str(out), encoding="unicode", xml_declaration=True)
        model2 = TM7Parser(out).parse()
        assert len(model2.threats) == 2
        titles = {t.title for t in model2.threats}
        assert "SQL Injection" in titles
        assert "XSS" in titles

    def test_skeleton_has_version(self, sample_model: ThreatModel, tmp_path: Path):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        out = tmp_path / "out.tm7"
        tree.write(str(out), encoding="unicode", xml_declaration=True)
        text = out.read_text(encoding="utf-8")
        assert "<Version>" in text

    def test_skeleton_has_knowledgebase(self, sample_model: ThreatModel):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        root = tree.getroot()
        ns = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model"
        kb = root.find(f"{{{ns}}}KnowledgeBase")
        assert kb is not None, "Generated TM7 must contain a KnowledgeBase element"
        # KB must have GenericElements and ThreatCategories at minimum
        ns_kb = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
        assert kb.find(f"{{{ns_kb}}}GenericElements") is not None
        assert kb.find(f"{{{ns_kb}}}ThreatCategories") is not None

    def test_skeleton_has_profile(self, sample_model: ThreatModel):
        gen = TM7Generator()
        tree = gen.generate(sample_model)
        root = tree.getroot()
        ns = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model"
        profile = root.find(f"{{{ns}}}Profile")
        assert profile is not None, "Generated TM7 must contain a Profile element"


# ===================================================================
# TM7 Parser Tests (sample files)
# ===================================================================


@pytest.mark.skipif(not _has_sample(SIMPLE_TM7), reason="Sample TM7 not found")
class TestTM7ParserSimple:
    def test_parse_elements(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        assert len(model.elements) == 3
        names = {e.name for e in model.elements}
        assert "User" in names
        assert "Web Application" in names
        assert "SQL Database" in names

    def test_element_types(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        types = {e.name: e.generic_type for e in model.elements}
        assert types["User"] == "GE.EI"
        assert types["Web Application"] == "GE.P"
        assert types["SQL Database"] == "GE.DS"

    def test_parse_flows(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        assert len(model.flows) == 4  # 5 lines minus 1 trust boundary

    def test_trust_boundaries_from_lines(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        assert len(model.boundaries) >= 1
        names = {tb.name for tb in model.boundaries}
        assert "Internet Boundary" in names

    def test_parse_threats(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        assert len(model.threats) == 10

    def test_threat_states(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        states = {t.state for t in model.threats}
        assert "Needs Investigation" in states
        assert "Mitigated" in states
        assert "Not Applicable" in states

    def test_threat_has_category(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        t = next(t for t in model.threats if t.title == "Potential SQL Injection Vulnerability for SQL Database")
        assert t.category == "Tampering"

    def test_threat_source_target_resolved(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        t = next(t for t in model.threats if t.title == "Potential SQL Injection Vulnerability for SQL Database")
        assert t.source == "Web Application"
        assert t.target == "SQL Database"

    def test_threat_priority(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        for t in model.threats:
            assert t.priority, f"Threat '{t.title}' has no priority"


@pytest.mark.skipif(not _has_sample(COMPLEX_TM7), reason="Complex sample TM7 not found")
class TestTM7ParserComplex:
    def test_parse_elements(self):
        model = TM7Parser(COMPLEX_TM7).parse()
        assert len(model.elements) == 6

    def test_parse_threats(self):
        model = TM7Parser(COMPLEX_TM7).parse()
        assert len(model.threats) == 43

    def test_trust_boundaries(self):
        model = TM7Parser(COMPLEX_TM7).parse()
        assert len(model.boundaries) >= 2


@pytest.mark.skipif(not _has_sample(AZ_TM7), reason="Azure sample TM7 not found")
class TestTM7ParserAzure:
    def test_parse_elements(self):
        model = TM7Parser(AZ_TM7).parse()
        assert len(model.elements) == 22

    def test_parse_flows(self):
        model = TM7Parser(AZ_TM7).parse()
        assert len(model.flows) >= 28  # 30 lines minus ~2 boundaries

    def test_parse_threats(self):
        model = TM7Parser(AZ_TM7).parse()
        assert len(model.threats) == 108


# ===================================================================
# TM7 Round-Trip Tests
# ===================================================================


@pytest.mark.skipif(not _has_sample(SIMPLE_TM7), reason="Sample TM7 not found")
class TestTM7RoundTrip:
    def test_tm7_to_md_to_tm7_elements(self, tmp_path: Path):
        model1 = TM7Parser(SIMPLE_TM7).parse()
        md = MarkdownGenerator().generate(model1)
        md_path = tmp_path / "model.md"
        md_path.write_text(md, encoding="utf-8")

        model2 = MarkdownParser(md_path).parse()
        gen = TM7Generator()
        tree = gen.generate(model2)
        tm7_path = tmp_path / "out.tm7"
        tree.write(str(tm7_path), encoding="unicode", xml_declaration=True)

        model3 = TM7Parser(tm7_path).parse()
        assert len(model3.elements) >= len(model1.elements)
        names1 = {e.name for e in model1.elements}
        names3 = {e.name for e in model3.elements}
        assert names1.issubset(names3)

    def test_tm7_to_md_to_tm7_threat_states(self, tmp_path: Path):
        model1 = TM7Parser(SIMPLE_TM7).parse()
        md = MarkdownGenerator().generate(model1)
        md_path = tmp_path / "model.md"
        md_path.write_text(md, encoding="utf-8")

        model2 = MarkdownParser(md_path).parse()
        gen = TM7Generator()
        tree = gen.generate(model2)
        tm7_path = tmp_path / "out.tm7"
        tree.write(str(tm7_path), encoding="unicode", xml_declaration=True)

        model3 = TM7Parser(tm7_path).parse()
        states1 = {t.title: t.state for t in model1.threats}
        states3 = {t.title: t.state for t in model3.threats}
        for title, state in states1.items():
            assert states3.get(title) == state, f"State mismatch for '{title}': {states3.get(title)} != {state}"

    def test_tm7_to_md_to_tm7_threat_categories(self, tmp_path: Path):
        model1 = TM7Parser(SIMPLE_TM7).parse()
        md = MarkdownGenerator().generate(model1)
        md_path = tmp_path / "model.md"
        md_path.write_text(md, encoding="utf-8")

        model2 = MarkdownParser(md_path).parse()
        gen = TM7Generator()
        tree = gen.generate(model2)
        tm7_path = tmp_path / "out.tm7"
        tree.write(str(tm7_path), encoding="unicode", xml_declaration=True)

        model3 = TM7Parser(tm7_path).parse()
        cats1 = {t.title: t.category for t in model1.threats}
        cats3 = {t.title: t.category for t in model3.threats}
        for title, cat in cats1.items():
            assert cats3.get(title) == cat, f"Category mismatch for '{title}': {cats3.get(title)} != {cat}"

    def test_tm7_to_md_to_tm7_threat_ids(self, tmp_path: Path):
        model1 = TM7Parser(SIMPLE_TM7).parse()
        md = MarkdownGenerator().generate(model1)
        md_path = tmp_path / "model.md"
        md_path.write_text(md, encoding="utf-8")

        model2 = MarkdownParser(md_path).parse()
        gen = TM7Generator()
        tree = gen.generate(model2)
        tm7_path = tmp_path / "out.tm7"
        tree.write(str(tm7_path), encoding="unicode", xml_declaration=True)

        model3 = TM7Parser(tm7_path).parse()
        ids1 = {t.title: t.id for t in model1.threats}
        ids3 = {t.title: t.id for t in model3.threats}
        for title, tid in ids1.items():
            assert ids3.get(title) == tid, f"ID mismatch for '{title}': {ids3.get(title)} != {tid}"


# ===================================================================
# Summary Tests
# ===================================================================


class TestSummary:
    def test_summary_counts(self, sample_model: ThreatModel):
        s = generate_summary(sample_model)
        assert s["name"] == "Test System"
        assert s["elements"] == 3
        assert s["data_flows"] == 2
        assert s["trust_boundaries"] == 2
        assert s["threats"]["total"] == 2

    def test_summary_state_counts(self, sample_model: ThreatModel):
        s = generate_summary(sample_model)
        assert s["threats"]["by_state"]["Needs Investigation"] == 1
        assert s["threats"]["by_state"]["Mitigated"] == 1

    def test_summary_category_counts(self, sample_model: ThreatModel):
        s = generate_summary(sample_model)
        assert s["threats"]["by_category"]["Tampering"] == 2

    def test_summary_element_list(self, sample_model: ThreatModel):
        s = generate_summary(sample_model)
        names = {e["name"] for e in s["element_list"]}
        assert names == {"User", "Web App", "Database"}

    def test_summary_threat_list(self, sample_model: ThreatModel):
        s = generate_summary(sample_model)
        assert len(s["threat_list"]) == 2
        titles = {t["title"] for t in s["threat_list"]}
        assert "SQL Injection" in titles

    @pytest.mark.skipif(not _has_sample(SIMPLE_TM7), reason="Sample TM7 not found")
    def test_summary_from_tm7(self):
        model = TM7Parser(SIMPLE_TM7).parse()
        s = generate_summary(model)
        assert s["elements"] == 3
        assert s["threats"]["total"] == 10


# ===================================================================
# Validator Tests
# ===================================================================


class TestValidator:
    def test_valid_model_passes(self, sample_md: Path):
        issues = validate_markdown(sample_md)
        # The sample has a "Not Applicable" without justification in our inline md?
        # Actually T3 has a justification. All should pass.
        # Check no structural issues
        structural = [i for i in issues if "Missing" in i or "No " in i]
        assert structural == []

    def test_missing_owner(self, tmp_path: Path):
        md = "# Threat Model: Test\n\n## Metadata\n\n## Elements\n\n| Name | Type | Generic Type | Notes |\n|---|---|---|---|\n| A | Process | GE.P | |\n\n## Data Flows\n\n| Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |\n|---|---|---|---|---|---|---|\n| F | A | A | HTTP | No | No | No |\n\n## Threats\n\n### T1: Threat\n- **Category:** Spoofing\n- **State:** Needs Investigation\n"
        p = tmp_path / "no_owner.md"
        p.write_text(md, encoding="utf-8")
        issues = validate_markdown(p)
        assert any("Missing owner" in i for i in issues)

    def test_mitigated_without_mitigation(self, tmp_path: Path):
        md = textwrap.dedent("""\
            # Threat Model: Test

            ## Metadata
            - **Owner:** Me

            ## Elements

            | Name | Type | Generic Type | Notes |
            |---|---|---|---|
            | A | Process | GE.P | |

            ## Data Flows

            | Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |
            |---|---|---|---|---|---|---|
            | F | A | A | HTTP | No | No | No |

            ## Threats

            ### T1: Bad
            - **Category:** Tampering
            - **State:** Mitigated
            - **Priority:** High
            - **Mitigation:**
        """)
        p = tmp_path / "no_mit.md"
        p.write_text(md, encoding="utf-8")
        issues = validate_markdown(p)
        assert any("Mitigated without mitigation" in i for i in issues)

    def test_not_applicable_without_justification(self, tmp_path: Path):
        md = textwrap.dedent("""\
            # Threat Model: Test

            ## Metadata
            - **Owner:** Me

            ## Elements

            | Name | Type | Generic Type | Notes |
            |---|---|---|---|
            | A | Process | GE.P | |

            ## Data Flows

            | Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |
            |---|---|---|---|---|---|---|
            | F | A | A | HTTP | No | No | No |

            ## Threats

            ### T1: NA
            - **Category:** Spoofing
            - **State:** Not Applicable
            - **Justification:**
        """)
        p = tmp_path / "no_just.md"
        p.write_text(md, encoding="utf-8")
        issues = validate_markdown(p)
        assert any("Not Applicable without justification" in i for i in issues)

    def test_unknown_flow_source(self, tmp_path: Path):
        md = textwrap.dedent("""\
            # Threat Model: Test

            ## Metadata
            - **Owner:** Me

            ## Elements

            | Name | Type | Generic Type | Notes |
            |---|---|---|---|
            | A | Process | GE.P | |

            ## Data Flows

            | Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |
            |---|---|---|---|---|---|---|
            | F | Unknown | A | HTTP | No | No | No |

            ## Threats

            ### T1: T
            - **Category:** Tampering
            - **State:** Needs Investigation
        """)
        p = tmp_path / "bad_src.md"
        p.write_text(md, encoding="utf-8")
        issues = validate_markdown(p)
        assert any("unknown source" in i for i in issues)


# ===================================================================
# STRIDE / State Map Tests
# ===================================================================


class TestMappings:
    def test_stride_categories_are_complete(self):
        assert set(STRIDE_CATEGORIES.keys()) == {"S", "T", "R", "I", "D", "E"}

    def test_stride_reverse_is_inverse(self):
        for code, name in STRIDE_CATEGORIES.items():
            assert STRIDE_REVERSE[name] == code

    def test_state_map_has_all_states(self):
        expected = {"NeedsInvestigation", "NotApplicable", "Mitigated", "NotStarted", "AutoGenerated"}
        assert set(STATE_MAP.keys()) == expected

    def test_state_map_reverse_is_inverse(self):
        for xml_val, display in STATE_MAP.items():
            assert STATE_MAP_REVERSE[display] == xml_val
