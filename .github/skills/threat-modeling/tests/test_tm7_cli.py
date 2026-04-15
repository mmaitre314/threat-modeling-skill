"""Unit tests for the threat-modeling skill (tm7_cli.py)."""

from __future__ import annotations

import re
import textwrap
import uuid
from pathlib import Path

import pytest

# Make imports work when running from this directory or the skill root.
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tm7_cli import (
    DataFlow,
    Diagram,
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
    _BORDER_BOUNDARY_GTYPE,
    _splice_section,
    _xml_escape,
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
        assert 'subgraph ' in md
        assert '["Internet"]' in md
        assert '["DMZ"]' in md
        # Trust boundaries should have red dashed styling
        assert 'stroke:red' in md
        assert 'stroke-dasharray' in md

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
# Text-Based Generation Tests
# ===================================================================


class TestTM7GeneratorText:
    """Tests for the template-safe text-based generation path."""

    def test_generate_text_returns_string(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert isinstance(text, str)
        assert "<ThreatModel" in text

    def test_generate_text_has_metadata(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert "Test System" in text
        assert "Alice" in text

    def test_generate_text_preserves_kb(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert "KnowledgeBase" in text
        assert "ThreatCategories" in text

    def test_generate_text_preserves_profile(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert "<Profile" in text
        assert "PromptedKb" in text

    def test_generate_text_has_elements(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert "User" in text
        assert "Web App" in text
        assert "Database" in text

    def test_generate_text_has_threats(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        assert "SQL Injection" in text
        assert "XSS" in text

    def test_write_produces_parseable_tm7(self, sample_model: ThreatModel, tmp_path: Path):
        out = tmp_path / "out.tm7"
        TM7Generator().write(sample_model, out)
        model2 = TM7Parser(out).parse()
        assert len(model2.elements) >= 3
        assert len(model2.threats) == 2

    def test_write_preserves_zid_attributes(self, sample_model: ThreatModel, tmp_path: Path):
        """z:Id attributes from the template must survive text-based generation."""
        out = tmp_path / "out.tm7"
        TM7Generator().write(sample_model, out)
        raw = out.read_bytes().decode("utf-8")
        ids = re.findall(r'[zc]:Id="[^"]+"', raw)
        assert len(ids) >= 2, f"Expected z:Id/c:Id attributes, found: {ids}"

    def test_write_no_xml_declaration(self, sample_model: ThreatModel, tmp_path: Path):
        """TMT files have no XML declaration — the output should start with <ThreatModel."""
        out = tmp_path / "out.tm7"
        TM7Generator().write(sample_model, out)
        raw = out.read_bytes().decode("utf-8")
        assert raw.startswith("<ThreatModel")

    def test_empty_model_produces_valid_output(self, tmp_path: Path):
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Empty")
        out = tmp_path / "empty.tm7"
        TM7Generator().write(model, out)
        model2 = TM7Parser(out).parse()
        assert model2.meta.name == "Empty"
        assert model2.elements == []
        assert model2.threats == []


# ===================================================================
# Helper Function Tests
# ===================================================================


class TestXmlEscape:
    def test_ampersand(self):
        assert _xml_escape("a&b") == "a&amp;b"

    def test_lt_gt(self):
        assert _xml_escape("<tag>") == "&lt;tag&gt;"

    def test_quotes(self):
        assert _xml_escape('say "hi"') == 'say &quot;hi&quot;'

    def test_no_change_for_plain_text(self):
        assert _xml_escape("hello world") == "hello world"


class TestSpliceSection:
    def test_replace_empty_tag(self):
        xml = '<Root><Items /><Other>keep</Other></Root>'
        result = _splice_section(xml, "Items", "<a>1</a>")
        assert "<a>1</a></Items>" in result
        assert "<Other>keep</Other>" in result

    def test_replace_existing_content(self):
        xml = '<Root><Items><old>x</old></Items></Root>'
        result = _splice_section(xml, "Items", "<new>y</new>")
        assert "<new>y</new>" in result
        assert "<old>x</old>" not in result

    def test_replace_with_empty(self):
        xml = '<Root><Items><old>x</old></Items></Root>'
        result = _splice_section(xml, "Items", "")
        assert "<Items></Items>" in result

    def test_preserves_namespace_prefix(self):
        xml = '<Root><ns:Items xmlns:ns="urn:test"><old>x</old></ns:Items></Root>'
        result = _splice_section(xml, "Items", "<a>1</a>")
        assert "<a>1</a></ns:Items>" in result


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
        tm7_path = tmp_path / "out.tm7"
        TM7Generator().write(model2, tm7_path)

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
        tm7_path = tmp_path / "out.tm7"
        TM7Generator().write(model2, tm7_path)

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
        tm7_path = tmp_path / "out.tm7"
        TM7Generator().write(model2, tm7_path)

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
        tm7_path = tmp_path / "out.tm7"
        TM7Generator().write(model2, tm7_path)

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


# ===================================================================
# Connector Layout Tests
# ===================================================================


class TestConnectorLayout:
    """Tests for direction-aware endpoints and bidirectional curve offsets."""

    def _build_model_with_bidir_flows(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="BiDir")
        a = Element(name="A", guid="aaaa", generic_type="GE.EI")
        b = Element(name="B", guid="bbbb", generic_type="GE.P")
        model.elements = [a, b]
        model.flows = [
            DataFlow(name="F1", guid="f1f1", source_guid="aaaa", target_guid="bbbb"),
            DataFlow(name="F2", guid="f2f2", source_guid="bbbb", target_guid="aaaa"),
        ]
        return model

    def test_bidirectional_flows_have_different_handle_y(self):
        model = self._build_model_with_bidir_flows()
        text = TM7Generator().generate_text(model)
        # Extract HandleY values — there should be two with different Y
        import re as _re
        handles = _re.findall(r"<HandleY[^>]*>(\d+)</HandleY>", text)
        assert len(handles) >= 2
        assert handles[0] != handles[1], "Bidirectional flows must have different HandleY for curves"

    def test_reverse_flow_uses_west_east_ports(self):
        model = self._build_model_with_bidir_flows()
        text = TM7Generator().generate_text(model)
        # First flow (A→B, left-to-right) should use East→West
        assert ">East</PortSource>" in text
        assert ">West</PortTarget>" in text
        # Second flow (B→A, right-to-left) should use West→East
        assert ">West</PortSource>" in text
        assert ">East</PortTarget>" in text

    def test_single_flow_has_curve_offset(self):
        """Even a single flow should have a handle offset (not on the straight line)."""
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Single")
        a = Element(name="A", guid="aaaa", generic_type="GE.EI")
        b = Element(name="B", guid="bbbb", generic_type="GE.P")
        model.elements = [a, b]
        model.flows = [
            DataFlow(name="F1", guid="f1f1", source_guid="aaaa", target_guid="bbbb"),
        ]
        text = TM7Generator().generate_text(model)
        import re as _re
        handle_y = _re.findall(r"<HandleY[^>]*>(\d+)</HandleY>", text)
        source_y = _re.findall(r"<SourceY[^>]*>(\d+)</SourceY>", text)
        assert len(handle_y) >= 1
        assert len(source_y) >= 1
        # Handle should be offset from the midpoint (curve upward for first flow)
        assert int(handle_y[0]) != int(source_y[0])


# ===================================================================
# z:Id Uniqueness Tests
# ===================================================================


class TestZIdUniqueness:
    def test_no_duplicate_zids(self, sample_model: ThreatModel):
        text = TM7Generator().generate_text(sample_model)
        import re as _re
        ids = _re.findall(r'z:Id="(i\d+)"', text)
        assert len(ids) == len(set(ids)), f"Duplicate z:Id values: {[x for x in ids if ids.count(x) > 1]}"

    def test_many_boundaries_unique_zids(self):
        """Multiple trust boundaries must each get a unique z:Id."""
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Multi TB")
        a = Element(name="A", guid=str(uuid.uuid4()), generic_type="GE.P")
        model.elements = [a]
        model.boundaries = [
            TrustBoundary(name="TB1", guid=str(uuid.uuid4()), elements=["A"]),
            TrustBoundary(name="TB2", guid=str(uuid.uuid4())),
            TrustBoundary(name="TB3", guid=str(uuid.uuid4())),
        ]
        text = TM7Generator().generate_text(model)
        import re as _re
        ids = _re.findall(r'z:Id="(i\d+)"', text)
        assert len(ids) == len(set(ids)), f"Duplicate z:Id values: {[x for x in ids if ids.count(x) > 1]}"


# ===================================================================
# Border Boundary / Annotation Filtering Tests
# ===================================================================


class TestBorderBoundaryFiltering:
    """Ensure BorderBoundary and Annotation elements are not parsed as DFD elements."""

    def test_border_boundary_constant_exists(self):
        assert _BORDER_BOUNDARY_GTYPE == "63e7829e-c420-4546-9336-0194c0113281"

    def test_border_boundary_excluded_from_elements(self, tmp_path: Path):
        """An element with the BorderBoundary GenericTypeId should not appear in elements."""
        # Use the simple_reference as a base (it has no border boundaries)
        # and inject a border boundary entry in Borders via the complex_reference
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        # Elements should not include any with the border boundary generic type
        for el in model.elements:
            assert el.generic_type != _BORDER_BOUNDARY_GTYPE, \
                f"BorderBoundary '{el.name}' leaked into elements"
            assert el.generic_type != "GE.A", \
                f"Annotation '{el.name}' leaked into elements"

    def test_border_boundary_parsed_as_trust_boundary(self, tmp_path: Path):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        tb_names = {tb.name for tb in model.boundaries}
        # Internet DMZ and Shared are BorderBoundary types in the reference
        assert "Internet DMZ" in tb_names
        assert "Shared" in tb_names

    def test_border_boundary_has_contained_elements(self, tmp_path: Path):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        dmz = next(tb for tb in model.boundaries if tb.name == "Internet DMZ")
        assert "Trading Web App" in dmz.elements
        assert "WAF" in dmz.elements


# ===================================================================
# Multi-Diagram Parsing Tests
# ===================================================================


class TestMultiDiagramParsing:
    """The complex_reference.tm7 has 3 drawing surfaces.  All must be parsed."""

    def test_elements_from_all_diagrams(self):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        names = {e.name for e in model.elements}
        # External Access diagram
        assert "External User" in names
        assert "WAF" in names
        # Internal Access diagram
        assert "Internal User" in names
        # Service Access diagram
        assert "Partner Service" in names
        # Deduped: Trading Web App appears in all 3 but only once in the list
        assert len([e for e in model.elements if e.name == "Trading Web App"]) == 1

    def test_flows_from_all_diagrams(self):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        # 6 from External Access + 2 from Internal Access + 2 from Service Access = 10
        assert len(model.flows) == 10

    def test_flow_guids_resolve_to_names(self):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        # Build map from ALL diagrams (flows use per-diagram local GUIDs)
        guid_to_name = {}
        for d in model.diagrams:
            for e in d.elements:
                guid_to_name[e.guid] = e.name
        for df in model.flows:
            assert df.source_guid in guid_to_name, \
                f"Flow '{df.name}' source GUID not in element map"
            assert df.target_guid in guid_to_name, \
                f"Flow '{df.name}' target GUID not in element map"

    def test_threats_from_all_diagrams(self):
        samples = Path(__file__).resolve().parent.parent.parent.parent.parent / "samples"
        complex_ref = samples / "complex_reference.tm7"
        if not complex_ref.exists():
            pytest.skip("complex_reference.tm7 not found")
        model = TM7Parser(complex_ref).parse()
        assert len(model.threats) == 43


# ===================================================================
# Nil GUID Fallback Tests
# ===================================================================


class TestNilGuidFallback:
    def test_unresolvable_threat_guids_use_nil(self):
        """Threats with unresolvable source/target/flow should use nil GUID, not empty string."""
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Nil GUID")
        model.elements = [Element(name="A", guid=str(uuid.uuid4()), generic_type="GE.P")]
        model.threats = [
            Threat(id="1", title="Orphan", category="Tampering", state="Needs Investigation",
                   priority="High", risk="High", description="No matching element",
                   source="NonExistent", target="AlsoMissing", flow="NoSuchFlow"),
        ]
        text = TM7Generator().generate_text(model)
        nil = "00000000-0000-0000-0000-000000000000"
        assert f"<b:FlowGuid>{nil}</b:FlowGuid>" in text
        assert f"<b:SourceGuid>{nil}</b:SourceGuid>" in text
        assert f"<b:TargetGuid>{nil}</b:TargetGuid>" in text
        # Must NOT contain empty GUID fields
        assert "<b:FlowGuid></b:FlowGuid>" not in text
        assert "<b:SourceGuid></b:SourceGuid>" not in text
        assert "<b:TargetGuid></b:TargetGuid>" not in text


# ===================================================================
# Multi-Diagram Markdown Format Tests
# ===================================================================


class TestMultiDiagramMarkdown:
    """Tests for the multi-diagram Markdown format."""

    def _multi_diagram_model(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Multi-Diagram")
        a = Element(name="A", guid="aaaa", generic_type="GE.EI")
        b = Element(name="B", guid="bbbb", generic_type="GE.P")
        c = Element(name="C", guid="cccc", generic_type="GE.DS")
        model.diagrams = [
            Diagram(name="Ext", elements=[a, b],
                    flows=[DataFlow(name="F1", guid="f1", source_guid="aaaa", target_guid="bbbb")],
                    boundaries=[TrustBoundary(name="TB1", guid="t1", elements=["A"])]),
            Diagram(name="Int", elements=[b, c],
                    flows=[DataFlow(name="F2", guid="f2", source_guid="bbbb", target_guid="cccc")],
                    boundaries=[]),
        ]
        model.threats = [Threat(id="1", title="X", category="Tampering",
                                state="Needs Investigation", priority="High")]
        return model

    def test_generates_diagram_sections(self):
        model = self._multi_diagram_model()
        md = MarkdownGenerator().generate(model)
        assert "## Diagram: Ext" in md
        assert "## Diagram: Int" in md
        # H3 subsections inside diagrams
        assert "### Elements" in md
        assert "### Data Flows" in md

    def test_each_diagram_has_own_elements(self):
        model = self._multi_diagram_model()
        md = MarkdownGenerator().generate(model)
        # Both diagrams should have their own tables
        assert md.count("### Elements") == 2
        assert md.count("### Data Flows") == 2

    def test_threats_at_top_level(self):
        model = self._multi_diagram_model()
        md = MarkdownGenerator().generate(model)
        assert "## Threats" in md

    def test_round_trip_preserves_diagrams(self, tmp_path: Path):
        model = self._multi_diagram_model()
        md = MarkdownGenerator().generate(model)
        p = tmp_path / "multi.md"
        p.write_text(md, encoding="utf-8")
        model2 = MarkdownParser(p).parse()
        assert len(model2.diagrams) == 2
        assert model2.diagrams[0].name == "Ext"
        assert model2.diagrams[1].name == "Int"
        assert len(model2.diagrams[0].elements) == 2
        assert len(model2.diagrams[1].elements) == 2
        assert len(model2.diagrams[0].flows) == 1
        assert len(model2.diagrams[1].flows) == 1

    def test_single_diagram_uses_flat_format(self, sample_model: ThreatModel):
        md = MarkdownGenerator().generate(sample_model)
        assert "## Diagram:" not in md
        assert "## Data Flow Diagram" in md
        assert "## Elements" in md

    def test_multi_diagram_tm7_generation(self):
        model = self._multi_diagram_model()
        text = TM7Generator().generate_text(model)
        # Should have 2 DrawingSurfaceModel entries
        assert text.count("DrawingSurfaceModel") >= 4  # open + close tags * 2
        assert ">Ext<" in text
        assert ">Int<" in text

    def test_multi_diagram_tm7_unique_zids(self):
        model = self._multi_diagram_model()
        text = TM7Generator().generate_text(model)
        import re as _re
        ids = _re.findall(r'z:Id="(i\d+)"', text)
        assert len(ids) == len(set(ids)), f"Duplicate z:Id values: {[x for x in ids if ids.count(x) > 1]}"


# ===================================================================
# Layout Wrapping Tests — ensure coordinates stay within canvas bounds
# ===================================================================


class TestLayoutWrapping:
    """Verify that the layout engine wraps to new rows for wide models."""

    MAX_CANVAS = 1200  # must match the value in tm7_cli.py _borders_xml

    def _wide_model(self) -> ThreatModel:
        """Create a model with many boundary groups that would exceed canvas width."""
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Wide")
        diag = Diagram(name="D1")
        for i in range(8):
            el = Element(name=f"Proc{i}", guid=str(uuid.uuid4()), generic_type="GE.P")
            diag.elements.append(el)
            diag.boundaries.append(
                TrustBoundary(name=f"TB{i}", guid=str(uuid.uuid4()), elements=[f"Proc{i}"])
            )
        model.diagrams = [diag]
        return model

    def test_all_elements_within_canvas_width(self):
        model = self._wide_model()
        text = TM7Generator().generate_text(model)
        import re as _re
        lefts = [int(v) for v in _re.findall(r"<Left[^>]*>(\d+)</Left>", text)]
        widths = [int(v) for v in _re.findall(r"<Width[^>]*>(\d+)</Width>", text)]
        max_right = max(l + w for l, w in zip(lefts, widths))
        assert max_right <= self.MAX_CANVAS + 200, \
            f"Elements extend to x={max_right}, expected within {self.MAX_CANVAS + 200}"

    def test_wrapping_produces_multiple_y_levels(self):
        model = self._wide_model()
        text = TM7Generator().generate_text(model)
        import re as _re
        tops = set(int(v) for v in _re.findall(r"<Top[^>]*>(\d+)</Top>", text))
        assert len(tops) > 1, "All elements on same row — wrapping did not occur"

    def test_small_model_stays_single_row(self):
        """A model with 2 boundary groups should not wrap."""
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Small")
        diag = Diagram(name="D1")
        for i in range(2):
            el = Element(name=f"Proc{i}", guid=str(uuid.uuid4()), generic_type="GE.P")
            diag.elements.append(el)
            diag.boundaries.append(
                TrustBoundary(name=f"TB{i}", guid=str(uuid.uuid4()), elements=[f"Proc{i}"])
            )
        model.diagrams = [diag]
        text = TM7Generator().generate_text(model)
        import re as _re
        # Stencil elements (not boundaries) should all be at the same base Top
        # Filter out BorderBoundary Top values by finding stencil tops
        tops = _re.findall(r'i:type="Stencil\w+".*?<Top[^>]*>(\d+)</Top>', text, re.DOTALL)
        unique = set(tops)
        assert len(unique) == 1, f"Expected single row, got y levels: {unique}"


class TestSameColumnConnectors:
    """Connectors between vertically stacked elements use South/North ports."""

    def _stacked_model(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Stacked")
        a = Element(name="A", guid="aaaa", generic_type="GE.P")
        b = Element(name="B", guid="bbbb", generic_type="GE.P")
        model.elements = [a, b]
        model.boundaries = [
            TrustBoundary(name="TB", guid=str(uuid.uuid4()), elements=["A", "B"])
        ]
        model.flows = [
            DataFlow(name="Down", guid="f1f1", source_guid="aaaa", target_guid="bbbb"),
        ]
        return model

    def test_vertical_flow_uses_south_north_ports(self):
        model = self._stacked_model()
        text = TM7Generator().generate_text(model)
        assert ">South</PortSource>" in text or ">North</PortSource>" in text, \
            "Vertical flow should use South or North ports"

    def test_vertical_flow_source_below_target(self):
        """Source Y coordinate should be at the bottom of the source element."""
        model = self._stacked_model()
        text = TM7Generator().generate_text(model)
        import re as _re
        source_y = _re.findall(r"<SourceY[^>]*>(\d+)</SourceY>", text)
        target_y = _re.findall(r"<TargetY[^>]*>(\d+)</TargetY>", text)
        # For a downward flow: SourceY (bottom of A) should be < TargetY (top of B)
        # (there's one connector, skip LineBoundary entries if any)
        assert int(source_y[0]) < int(target_y[0])


class TestParallelConnectors:
    """Multiple flows between the same elements get offset endpoints."""

    def _parallel_model(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = ThreatModelMeta(name="Parallel")
        a = Element(name="A", guid="aaaa", generic_type="GE.EI")
        b = Element(name="B", guid="bbbb", generic_type="GE.P")
        model.elements = [a, b]
        model.flows = [
            DataFlow(name="F1", guid="f1f1", source_guid="aaaa", target_guid="bbbb"),
            DataFlow(name="F2", guid="f2f2", source_guid="aaaa", target_guid="bbbb"),
        ]
        return model

    def test_parallel_flows_have_different_endpoints(self):
        model = self._parallel_model()
        text = TM7Generator().generate_text(model)
        import re as _re
        sources = _re.findall(
            r"<SourceX[^>]*>(\d+)</SourceX>.*?<SourceY[^>]*>(\d+)</SourceY>",
            text, re.DOTALL)
        targets = _re.findall(
            r"<TargetX[^>]*>(\d+)</TargetX>.*?<TargetY[^>]*>(\d+)</TargetY>",
            text, re.DOTALL)
        # Both connectors should have DIFFERENT Y coordinates
        assert len(sources) >= 2
        assert sources[0] != sources[1], \
            "Parallel flows must have different source endpoints"
