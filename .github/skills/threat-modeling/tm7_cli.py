#!/usr/bin/env python3
"""
Threat Modeling CLI — Convert between Markdown threat models and TM7 XML files.

TM7 is the XML format used by the Microsoft Threat Modeling Tool.
This tool provides a human-friendly Markdown+Mermaid intermediate format
for authoring and reviewing threat models, with round-tripping to/from TM7.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# XML namespace constants
# ---------------------------------------------------------------------------

NS_TM = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model"
NS_ABS = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts"
NS_KB = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
NS_ARR = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
NS_SER = "http://schemas.microsoft.com/2003/10/Serialization/"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

# Register all namespaces so ET preserves prefixes on round-trip
_NS_MAP = {
    "": NS_TM,
    "a": NS_KB,
    "b": NS_ARR,
    "c": NS_SER,
    "i": NS_XSI,
    "d": NS_ABS,
}
for _prefix, _uri in _NS_MAP.items():
    ET.register_namespace(_prefix, _uri)


def _tag(ns: str, local: str) -> str:
    return f"{{{ns}}}{local}"


# Well-known GenericTypeId for BorderBoundary (box-shaped trust boundaries)
_BORDER_BOUNDARY_GTYPE = "63e7829e-c420-4546-9336-0194c0113281"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ThreatModelMeta:
    name: str = ""
    owner: str = ""
    reviewer: str = ""
    description: str = ""
    assumptions: str = ""
    external_dependencies: str = ""
    contributors: str = ""
    date: str = ""


@dataclass
class Element:
    name: str = ""
    guid: str = ""
    generic_type: str = ""  # GE.EI, GE.P, GE.DS
    type_id: str = ""  # SE.P.TMCore.WebApp etc.
    notes: str = ""
    out_of_scope: bool = False
    properties: dict = field(default_factory=dict)
    # Layout (optional, for round-trip)
    x: float = 0.0
    y: float = 0.0
    width: float = 100.0
    height: float = 100.0


@dataclass
class DataFlow:
    name: str = ""
    guid: str = ""
    source_guid: str = ""
    target_guid: str = ""
    generic_type: str = "GE.DF"
    type_id: str = ""
    protocol: str = ""
    authenticates_source: str = "Not Selected"
    authenticates_destination: str = "Not Selected"
    provides_confidentiality: str = "No"
    provides_integrity: str = "No"
    out_of_scope: bool = False
    properties: dict = field(default_factory=dict)


@dataclass
class TrustBoundary:
    name: str = ""
    guid: str = ""
    generic_type: str = "GE.TB"
    elements: list[str] = field(default_factory=list)  # element names


@dataclass
class Threat:
    id: str = ""
    title: str = ""
    category: str = ""  # S, T, R, I, D, E
    state: str = "Needs Investigation"
    priority: str = ""
    risk: str = ""
    description: str = ""
    source: str = ""  # element name
    target: str = ""  # element name
    flow: str = ""  # data flow name
    mitigation: str = ""
    justification: str = ""
    # Internal TM7 fields for round-trip
    source_guid: str = ""
    target_guid: str = ""
    flow_guid: str = ""
    drawing_surface_guid: str = ""
    interaction_key: str = ""
    changed_by: str = ""
    modified_at: str = ""
    threat_type_id: str = ""


@dataclass
class Diagram:
    """A single drawing surface (DFD diagram page) in the threat model."""
    name: str = ""
    guid: str = ""
    elements: list[Element] = field(default_factory=list)
    flows: list[DataFlow] = field(default_factory=list)
    boundaries: list[TrustBoundary] = field(default_factory=list)


@dataclass
class ThreatModel:
    meta: ThreatModelMeta = field(default_factory=ThreatModelMeta)
    diagrams: list[Diagram] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)

    # Convenience flat accessors (union across all diagrams)
    @property
    def elements(self) -> list[Element]:
        seen: set[str] = set()
        result: list[Element] = []
        for d in self.diagrams:
            for e in d.elements:
                if e.name not in seen:
                    seen.add(e.name)
                    result.append(e)
        return result

    @elements.setter
    def elements(self, value: list[Element]):
        if not self.diagrams:
            self.diagrams.append(Diagram())
        self.diagrams[0].elements = value

    @property
    def flows(self) -> list[DataFlow]:
        return [f for d in self.diagrams for f in d.flows]

    @flows.setter
    def flows(self, value: list[DataFlow]):
        if not self.diagrams:
            self.diagrams.append(Diagram())
        self.diagrams[0].flows = value

    @property
    def boundaries(self) -> list[TrustBoundary]:
        merged: dict[str, TrustBoundary] = {}
        for d in self.diagrams:
            for tb in d.boundaries:
                if tb.name in merged:
                    for en in tb.elements:
                        if en not in merged[tb.name].elements:
                            merged[tb.name].elements.append(en)
                else:
                    merged[tb.name] = TrustBoundary(
                        name=tb.name, guid=tb.guid,
                        generic_type=tb.generic_type,
                        elements=list(tb.elements))
        return list(merged.values())

    @boundaries.setter
    def boundaries(self, value: list[TrustBoundary]):
        if not self.diagrams:
            self.diagrams.append(Diagram())
        self.diagrams[0].boundaries = value


# ---------------------------------------------------------------------------
# STRIDE helpers
# ---------------------------------------------------------------------------

STRIDE_CATEGORIES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

STRIDE_REVERSE = {v: k for k, v in STRIDE_CATEGORIES.items()}

STATE_MAP = {
    "NeedsInvestigation": "Needs Investigation",
    "NotApplicable": "Not Applicable",
    "Mitigated": "Mitigated",
    "NotStarted": "Not Started",
    "AutoGenerated": "Auto Generated",
}
STATE_MAP_REVERSE = {v: k for k, v in STATE_MAP.items()}


# ---------------------------------------------------------------------------
# TM7 Parser — TM7 XML → ThreatModel
# ---------------------------------------------------------------------------


class TM7Parser:
    """Parse a TM7 XML file into a ThreatModel."""

    def __init__(self, path: str | Path):
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

    def parse(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = self._parse_meta()

        # Build one Diagram per DrawingSurfaceModel
        for ds in self._iter_drawing_surfaces():
            diag = self._parse_diagram(ds)
            model.diagrams.append(diag)

        model.threats = self._parse_threats()

        # Build guid→name map across ALL diagram copies for threat resolution
        guid_to_name: dict[str, str] = {}
        for d in model.diagrams:
            for el in d.elements:
                guid_to_name[el.guid] = el.name
        flow_guid_to_name = {f.guid: f.name for f in model.flows}
        for t in model.threats:
            if t.source_guid and t.source_guid in guid_to_name:
                t.source = guid_to_name[t.source_guid]
            if t.target_guid and t.target_guid in guid_to_name:
                t.target = guid_to_name[t.target_guid]
            if t.flow_guid and t.flow_guid in flow_guid_to_name:
                t.flow = flow_guid_to_name[t.flow_guid]

        return model

    def _parse_meta(self) -> ThreatModelMeta:
        meta_el = self.root.find(_tag(NS_TM, "MetaInformation"))
        if meta_el is None:
            return ThreatModelMeta()
        m = ThreatModelMeta()
        m.name = self._text(meta_el, "ThreatModelName")
        m.owner = self._text(meta_el, "Owner")
        m.reviewer = self._text(meta_el, "Reviewer")
        m.description = self._text(meta_el, "HighLevelSystemDescription")
        m.assumptions = self._text(meta_el, "Assumptions")
        m.external_dependencies = self._text(meta_el, "ExternalDependencies")
        m.contributors = self._text(meta_el, "Contributors")
        return m

    def _iter_drawing_surfaces(self):
        """Yield all DrawingSurfaceModel elements."""
        ds_list = self.root.find(_tag(NS_TM, "DrawingSurfaceList"))
        if ds_list is None:
            return
        for ds in ds_list.findall(_tag(NS_TM, "DrawingSurfaceModel")):
            yield ds

    def _parse_diagram(self, ds) -> Diagram:
        """Parse a single DrawingSurfaceModel into a Diagram."""
        diag = Diagram()

        # Diagram name from Header element
        header = ds.find(_tag(NS_TM, "Header"))
        if header is not None and header.text:
            diag.name = header.text.strip()

        # Diagram GUID
        guid_el = ds.find(_tag(NS_ABS, "Guid"))
        if guid_el is not None and guid_el.text:
            diag.guid = guid_el.text.strip()

        # --- Borders: elements + border boundaries ---
        borders = ds.find(_tag(NS_TM, "Borders"))
        stencil_rects: list[tuple[str, float, float, float, float]] = []
        boundary_entries: list[tuple[TrustBoundary, float, float, float, float]] = []

        if borders is not None:
            for kv in borders:
                val = kv.find(_tag(NS_ARR, "Value"))
                if val is None:
                    continue
                gtype = self._child_text(val, NS_ABS, "GenericTypeId")

                x = float(self._child_text(val, NS_ABS, "Left") or "0")
                y = float(self._child_text(val, NS_ABS, "Top") or "0")
                w = float(self._child_text(val, NS_ABS, "Width") or "0")
                h = float(self._child_text(val, NS_ABS, "Height") or "0")

                is_boundary = (
                    (gtype and gtype.startswith("GE.TB"))
                    or gtype == _BORDER_BOUNDARY_GTYPE
                )

                if is_boundary:
                    tb = TrustBoundary()
                    tb.guid = self._child_text(val, NS_ABS, "Guid")
                    tb.generic_type = gtype if gtype.startswith("GE.TB") else "GE.TB.B"
                    props = val.find(_tag(NS_ABS, "Properties"))
                    if props is not None:
                        tb.name, _, _ = self._parse_props(props)
                    if not tb.name:
                        tb.name = gtype
                    boundary_entries.append((tb, x, y, w, h))
                elif gtype == "GE.A":
                    continue  # skip annotations
                else:
                    el = Element()
                    el.guid = self._child_text(val, NS_ABS, "Guid")
                    el.generic_type = gtype
                    el.type_id = self._child_text(val, NS_ABS, "TypeId")
                    el.x = x
                    el.y = y
                    el.width = w
                    el.height = h
                    props = val.find(_tag(NS_ABS, "Properties"))
                    if props is not None:
                        el.name, el.out_of_scope, el.properties = self._parse_props(props)
                    if not el.name:
                        el.name = el.type_id or el.generic_type
                    diag.elements.append(el)
                    stencil_rects.append((el.name, x, y, w, h))

        # Sort elements by X coordinate for readable left-to-right order
        diag.elements.sort(key=lambda e: e.x)

        # Geometric containment for border boundaries
        for tb, bx, by, bw, bh in boundary_entries:
            for el_name, ex, ey, ew, eh in stencil_rects:
                if (ex >= bx and ey >= by
                        and ex + ew <= bx + bw and ey + eh <= by + bh):
                    tb.elements.append(el_name)
            diag.boundaries.append(tb)

        # --- Lines: flows + line boundaries ---
        lines = ds.find(_tag(NS_TM, "Lines"))
        if lines is not None:
            for kv in lines:
                val = kv.find(_tag(NS_ARR, "Value"))
                if val is None:
                    continue

                gtype_check = self._child_text(val, NS_ABS, "GenericTypeId")
                typeid_check = self._child_text(val, NS_ABS, "TypeId")

                if (gtype_check and "TB" in gtype_check) or (typeid_check and ".TB." in typeid_check):
                    tb = TrustBoundary()
                    tb.guid = self._child_text(val, NS_ABS, "Guid")
                    tb.generic_type = gtype_check or "GE.TB"
                    props = val.find(_tag(NS_ABS, "Properties"))
                    if props is not None:
                        tb.name, _, _ = self._parse_props(props)
                    if not tb.name:
                        tb.name = typeid_check or gtype_check
                    diag.boundaries.append(tb)
                    continue

                df = DataFlow()
                df.guid = self._child_text(val, NS_ABS, "Guid")
                df.generic_type = self._child_text(val, NS_ABS, "GenericTypeId")
                df.type_id = self._child_text(val, NS_ABS, "TypeId")
                df.source_guid = self._child_text(val, NS_ABS, "SourceGuid")
                df.target_guid = self._child_text(val, NS_ABS, "TargetGuid")

                props = val.find(_tag(NS_ABS, "Properties"))
                if props is not None:
                    df.name, df.out_of_scope, extra = self._parse_props(props)
                    df.authenticates_source = extra.get("authenticatesSource", "Not Selected")
                    df.authenticates_destination = extra.get("authenticatesDestination", "Not Selected")
                    df.provides_confidentiality = extra.get("providesConfidentiality", "No")
                    df.provides_integrity = extra.get("providesIntegrity", "No")
                    df.properties = extra

                if not df.name:
                    df.name = df.type_id or df.generic_type

                diag.flows.append(df)

        return diag

    def _parse_threats(self) -> list[Threat]:
        threats = []
        ti_root = self.root.find(_tag(NS_TM, "ThreatInstances"))
        if ti_root is None:
            return threats

        for kv in ti_root:
            val = kv.find(_tag(NS_ARR, "Value"))
            if val is None:
                continue
            t = Threat()
            t.id = self._child_text(val, NS_KB, "Id") or ""
            t.source_guid = self._child_text(val, NS_KB, "SourceGuid") or ""
            t.target_guid = self._child_text(val, NS_KB, "TargetGuid") or ""
            t.flow_guid = self._child_text(val, NS_KB, "FlowGuid") or ""
            t.drawing_surface_guid = self._child_text(val, NS_KB, "DrawingSurfaceGuid") or ""
            t.interaction_key = self._child_text(val, NS_KB, "InteractionKey") or ""
            t.changed_by = self._child_text(val, NS_KB, "ChangedBy") or ""
            t.modified_at = self._child_text(val, NS_KB, "ModifiedAt") or ""
            t.priority = self._child_text(val, NS_KB, "Priority") or ""
            t.threat_type_id = self._child_text(val, NS_KB, "TypeId") or ""

            raw_state = self._child_text(val, NS_KB, "State") or "NeedsInvestigation"
            t.state = STATE_MAP.get(raw_state, raw_state)

            # Properties dict
            props_el = val.find(_tag(NS_KB, "Properties"))
            if props_el is not None:
                for pkv in props_el:
                    pk = pkv.find(_tag(NS_ARR, "Key"))
                    pv = pkv.find(_tag(NS_ARR, "Value"))
                    if pk is not None and pv is not None:
                        key = pk.text or ""
                        value = pv.text or ""
                        if key == "Title":
                            t.title = value
                        elif key == "UserThreatCategory":
                            t.category = value
                        elif key == "UserThreatDescription":
                            t.description = value
                        elif key == "Priority":
                            t.priority = t.priority or value
                        elif key == "f9e02b87-2914-407e-bd11-97353ef43162":
                            t.risk = value
                        elif key == "44490cdf-6399-4291-9bde-03dca6f03c11":
                            t.mitigation = value

            # Map full category name to code
            if t.category in STRIDE_REVERSE:
                t.category = t.category  # keep full name
            elif t.category in STRIDE_CATEGORIES:
                t.category = STRIDE_CATEGORIES[t.category]

            threats.append(t)

        return threats

    # --- XML helpers ---

    def _text(self, parent, tag_local: str) -> str:
        el = parent.find(_tag(NS_TM, tag_local))
        if el is not None and el.text:
            return el.text.strip()
        return ""

    def _child_text(self, parent, ns: str, tag_local: str) -> str:
        el = parent.find(_tag(ns, tag_local))
        if el is not None and el.text:
            return el.text.strip()
        return ""

    def _parse_props(self, props_el) -> tuple[str, bool, dict]:
        """Extract name, out_of_scope, and property dict from Properties element."""
        name = ""
        out_of_scope = False
        extra = {}

        for anytype in props_el:
            display_name_el = anytype.find(_tag(NS_KB, "DisplayName"))
            name_el = anytype.find(_tag(NS_KB, "Name"))
            value_el = anytype.find(_tag(NS_KB, "Value"))

            display_name = (display_name_el.text or "").strip() if display_name_el is not None else ""
            prop_name = (name_el.text or "").strip() if name_el is not None else ""

            # Value can be text, boolean, or a list with SelectedIndex
            value = ""
            if value_el is not None:
                nil = value_el.get(f"{{{NS_XSI}}}nil")
                if nil == "true":
                    value = ""
                elif value_el.text:
                    value = value_el.text.strip()

            # List attributes: get selected value from SelectedIndex
            idx_el = anytype.find(_tag(NS_KB, "SelectedIndex"))
            if idx_el is not None and value_el is not None:
                options = [s.text or "" for s in value_el]
                idx = int(idx_el.text or "0")
                if 0 <= idx < len(options):
                    value = options[idx]

            if display_name == "Name":
                name = value
            elif display_name == "Out Of Scope":
                out_of_scope = value.lower() in ("true", "yes")
            elif prop_name:
                extra[prop_name] = value
            elif display_name:
                extra[display_name] = value

        return name, out_of_scope, extra


# ---------------------------------------------------------------------------
# Markdown Parser — Markdown → ThreatModel
# ---------------------------------------------------------------------------


class MarkdownParser:
    """Parse a Markdown threat model file into a ThreatModel."""

    def __init__(self, path: str | Path):
        self.text = Path(path).read_text(encoding="utf-8")

    def parse(self) -> ThreatModel:
        model = ThreatModel()
        model.meta = self._parse_meta()

        # Detect multi-diagram format: look for ## Diagram: sections
        diagram_sections = list(re.finditer(
            r"^## Diagram:\s*(.+?)\s*$(.*?)(?=^## |\Z)",
            self.text, re.MULTILINE | re.DOTALL))

        if diagram_sections:
            for dm in diagram_sections:
                diag = Diagram(name=dm.group(1).strip())
                body = dm.group(2)
                diag.elements = self._parse_elements_from(body, level=3)
                diag.flows = self._parse_flows_from(body, level=3)
                diag.boundaries = self._parse_boundaries_from(body, level=3)
                model.diagrams.append(diag)
        else:
            # Legacy flat format: single unnamed diagram
            diag = Diagram()
            diag.elements = self._parse_elements_from(self.text, level=2)
            diag.flows = self._parse_flows_from(self.text, level=2)
            diag.boundaries = self._parse_boundaries_from(self.text, level=2)
            model.diagrams.append(diag)

        model.threats = self._parse_threats()
        return model

    def _get_section(self, heading: str, level: int = 2) -> str:
        pattern = rf"^{'#' * level}\s+{re.escape(heading)}\s*$(.*?)(?=^{'#' * level}\s|\Z)"
        m = re.search(pattern, self.text, re.MULTILINE | re.DOTALL)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _get_section_from(text: str, heading: str, level: int = 2) -> str:
        pattern = rf"^{'#' * level}\s+{re.escape(heading)}\s*$(.*?)(?=^{'#' * level}\s|\Z)"
        m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
        return m.group(1).strip() if m else ""

    def _parse_meta(self) -> ThreatModelMeta:
        meta = ThreatModelMeta()

        # Title from H1
        m = re.search(r"^#\s+Threat Model:\s*(.+)$", self.text, re.MULTILINE)
        if m:
            meta.name = m.group(1).strip()

        section = self._get_section("Metadata")
        for line in section.splitlines():
            line = line.strip()
            m_field = re.match(r"^-\s+\*\*(.+?)\*\*\s*(.*)$", line)
            if m_field:
                key, val = m_field.group(1).strip().rstrip(":").lower(), m_field.group(2).strip()
                if key == "owner":
                    meta.owner = val
                elif key == "reviewer":
                    meta.reviewer = val
                elif key == "date":
                    meta.date = val
                elif key == "description":
                    meta.description = val
                elif key == "assumptions":
                    meta.assumptions = val
                elif key in ("external dependencies", "dependencies"):
                    meta.external_dependencies = val

        return meta

    def _parse_table(self, section_text: str) -> list[dict[str, str]]:
        """Parse a Markdown table into a list of dicts."""
        lines = [l.strip() for l in section_text.splitlines() if l.strip()]
        # Find header row (contains |)
        table_lines = [l for l in lines if "|" in l]
        if len(table_lines) < 3:  # header + separator + at least 1 row
            return []

        header = [c.strip() for c in table_lines[0].split("|") if c.strip()]
        rows = []
        for row_line in table_lines[2:]:  # skip separator
            cells = [c.strip() for c in row_line.split("|")]
            # Remove empty first/last from leading/trailing |
            if cells and not cells[0]:
                cells = cells[1:]
            if cells and not cells[-1]:
                cells = cells[:-1]
            if len(cells) >= len(header):
                row = {header[i]: cells[i] for i in range(len(header))}
                rows.append(row)
        return rows

    def _parse_elements_from(self, text: str, level: int = 2) -> list[Element]:
        section = self._get_section_from(text, "Elements", level)
        rows = self._parse_table(section)
        elements = []
        for row in rows:
            el = Element()
            el.name = row.get("Name", "")
            el.generic_type = row.get("Generic Type", row.get("Type ID", ""))
            el.type_id = row.get("Type ID", "")
            el.notes = row.get("Notes", "")
            raw_type = row.get("Type", "")
            if not el.generic_type:
                el.generic_type = {
                    "External Interactor": "GE.EI",
                    "Process": "GE.P",
                    "Data Store": "GE.DS",
                }.get(raw_type, "")
            el.guid = str(uuid.uuid4())
            elements.append(el)
        return elements

    def _parse_flows_from(self, text: str, level: int = 2) -> list[DataFlow]:
        section = self._get_section_from(text, "Data Flows", level)
        rows = self._parse_table(section)
        flows = []
        for row in rows:
            df = DataFlow()
            df.name = row.get("Name", "")
            df.source_guid = row.get("Source", "")  # name, resolved later
            df.target_guid = row.get("Target", "")  # name, resolved later
            df.protocol = row.get("Protocol", "")
            df.authenticates_source = row.get("Authenticates Source", "Not Selected")
            df.provides_confidentiality = row.get("Provides Confidentiality", "No")
            df.provides_integrity = row.get("Provides Integrity", "No")
            df.guid = str(uuid.uuid4())
            flows.append(df)
        return flows

    def _parse_boundaries_from(self, text: str, level: int = 2) -> list[TrustBoundary]:
        section = self._get_section_from(text, "Trust Boundaries", level)
        rows = self._parse_table(section)
        boundaries = []
        for row in rows:
            tb = TrustBoundary()
            tb.name = row.get("Name", "")
            tb.elements = [e.strip() for e in row.get("Elements", "").split(",") if e.strip()]
            tb.guid = str(uuid.uuid4())
            boundaries.append(tb)
        return boundaries

    def _parse_threats(self) -> list[Threat]:
        threats = []
        # Find the Threats section
        threats_section = self._get_section("Threats")
        if not threats_section:
            return threats

        # Split into individual threat blocks by ### headings
        blocks = re.split(r"^###\s+", threats_section, flags=re.MULTILINE)
        for block in blocks:
            if not block.strip():
                continue
            t = Threat()

            # Title line: "T1: SQL Injection on SQL Database" or "1: Title"
            first_line, _, rest = block.partition("\n")
            m = re.match(r"T?(\d+):\s*(.+)", first_line.strip())
            if m:
                t.id = m.group(1)
                t.title = m.group(2).strip()
            else:
                t.title = first_line.strip()

            # Parse bullet fields
            for line in rest.splitlines():
                line = line.strip()
                m_field = re.match(r"^-\s+\*\*(.+?)\*\*\s*(.*)$", line)
                if m_field:
                    key = m_field.group(1).strip().rstrip(":").lower()
                    val = m_field.group(2).strip()
                    if key == "category":
                        t.category = val
                    elif key == "state":
                        t.state = val
                    elif key == "priority":
                        t.priority = val
                    elif key == "risk":
                        t.risk = val
                    elif key == "description":
                        t.description = val
                    elif key == "target":
                        t.target = val
                    elif key == "source":
                        t.source = val
                    elif key == "flow":
                        t.flow = val
                    elif key == "mitigation":
                        t.mitigation = val
                    elif key == "justification":
                        t.justification = val

            threats.append(t)

        return threats


# ---------------------------------------------------------------------------
# Markdown Generator — ThreatModel → Markdown
# ---------------------------------------------------------------------------


class MarkdownGenerator:
    """Generate a Markdown threat model from a ThreatModel."""

    def generate(self, model: ThreatModel) -> str:
        lines = []
        meta = model.meta

        lines.append(f"# Threat Model: {meta.name or 'Untitled'}")
        lines.append("")
        lines.append("## Metadata")
        lines.append(f"- **Owner:** {meta.owner}")
        lines.append(f"- **Reviewer:** {meta.reviewer}")
        lines.append(f"- **Date:** {meta.date or datetime.now().strftime('%Y-%m-%d')}")
        lines.append(f"- **Description:** {meta.description}")
        lines.append(f"- **Assumptions:** {meta.assumptions}")
        lines.append(f"- **External Dependencies:** {meta.external_dependencies}")
        lines.append("")

        diagrams = model.diagrams if model.diagrams else [Diagram()]
        if len(diagrams) <= 1:
            # Single diagram: flat format (backward compatible)
            diag = diagrams[0]
            lines.extend(self._diagram_body(diag, model.elements, model.flows,
                                            model.boundaries, h_offset=0))
        else:
            # Multiple diagrams: per-diagram sections
            for diag in diagrams:
                lines.append(f"## Diagram: {diag.name or 'Untitled'}")
                lines.append("")
                lines.extend(self._diagram_body(diag, diag.elements, diag.flows,
                                                diag.boundaries, h_offset=1))

        # Threats (always at top level)
        lines.append("## Threats")
        lines.append("")
        for i, t in enumerate(model.threats, 1):
            tid = t.id or f"T{i}"
            lines.append(f"### {tid}: {t.title}")
            lines.append(f"- **Category:** {t.category}")
            lines.append(f"- **State:** {t.state}")
            lines.append(f"- **Priority:** {t.priority}")
            lines.append(f"- **Risk:** {t.risk}")
            lines.append(f"- **Description:** {t.description}")
            lines.append(f"- **Target:** {t.target}")
            lines.append(f"- **Source:** {t.source}")
            lines.append(f"- **Flow:** {t.flow}")
            lines.append(f"- **Mitigation:** {t.mitigation}")
            lines.append(f"- **Justification:** {t.justification}")
            lines.append("")

        return "\n".join(lines)

    def _diagram_body(self, diag: Diagram, elements: list[Element],
                      flows: list[DataFlow], boundaries: list[TrustBoundary],
                      h_offset: int = 0) -> list[str]:
        """Generate DFD, elements table, flows table, boundaries table.

        *h_offset*: 0 → H2+H3 headings (flat), 1 → H3+H4 headings (per-diagram).
        """
        h2 = "#" * (2 + h_offset)
        lines: list[str] = []

        # DFD
        lines.append(f"{h2} Data Flow Diagram")
        lines.append("")
        lines.append("```mermaid")
        lines.append("graph LR")
        lines.extend(self._mermaid_dfd(elements, flows, boundaries))
        lines.append("```")
        lines.append("")

        # Elements table
        lines.append(f"{h2} Elements")
        lines.append("")
        lines.append("| Name | Type | Generic Type | Notes |")
        lines.append("|------|------|-------------|-------|")
        for el in elements:
            type_label = {
                "GE.EI": "External Interactor",
                "GE.P": "Process",
                "GE.DS": "Data Store",
            }.get(el.generic_type, el.generic_type)
            lines.append(f"| {el.name} | {type_label} | {el.generic_type} | {el.notes} |")
        lines.append("")

        # Data Flows table
        guid_to_name = {e.guid: e.name for e in elements}
        lines.append(f"{h2} Data Flows")
        lines.append("")
        lines.append("| Name | Source | Target | Protocol | Authenticates Source | Provides Confidentiality | Provides Integrity |")
        lines.append("|------|--------|--------|----------|---------------------|-------------------------|-------------------|")
        for df in flows:
            src = guid_to_name.get(df.source_guid, df.source_guid)
            tgt = guid_to_name.get(df.target_guid, df.target_guid)
            protocol = df.type_id or df.protocol
            lines.append(
                f"| {df.name} | {src} | {tgt} | {protocol} "
                f"| {df.authenticates_source} | {df.provides_confidentiality} | {df.provides_integrity} |"
            )
        lines.append("")

        # Trust Boundaries
        if boundaries:
            lines.append(f"{h2} Trust Boundaries")
            lines.append("")
            lines.append("| Name | Elements |")
            lines.append("|------|----------|")
            for tb in boundaries:
                elems = ", ".join(tb.elements) if tb.elements else ""
                lines.append(f"| {tb.name} | {elems} |")
            lines.append("")

        return lines

    def _mermaid_dfd(self, elements: list[Element], flows: list[DataFlow],
                     boundaries: list[TrustBoundary]) -> list[str]:
        lines = []
        guid_to_name = {e.guid: e.name for e in elements}
        # Sanitize name for Mermaid ID
        def mid(name: str) -> str:
            return re.sub(r"[^a-zA-Z0-9_]", "", name.replace(" ", "_"))

        # Track which elements are in a boundary
        in_boundary = set()
        for tb in boundaries:
            for ename in tb.elements:
                in_boundary.add(ename)

        # Render boundaries as subgraphs with red dashed styling
        tb_ids: list[str] = []
        for tb in boundaries:
            sg_id = mid(tb.name)
            tb_ids.append(sg_id)
            lines.append(f'    subgraph {sg_id}["{tb.name}"]')
            for ename in tb.elements:
                el = next((e for e in elements if e.name == ename), None)
                if el:
                    lines.append(f"        {self._mermaid_node(el)}")
            lines.append("    end")
        for sg_id in tb_ids:
            lines.append(f"    style {sg_id} fill:transparent,stroke:red,stroke-width:2px,stroke-dasharray: 5 5,color:red")

        # Render elements not in any boundary
        for el in elements:
            if el.name not in in_boundary:
                lines.append(f"    {self._mermaid_node(el)}")

        # Render flows – sort so forward (left-to-right) edges come first
        # to guide Mermaid's graph LR rank assignment.
        el_order = {e.name: i for i, e in enumerate(elements)}
        def _flow_sort_key(df):
            sn = guid_to_name.get(df.source_guid, df.source_guid)
            tn = guid_to_name.get(df.target_guid, df.target_guid)
            si, ti = el_order.get(sn, 999), el_order.get(tn, 999)
            forward = 0 if si <= ti else 1
            return (min(si, ti), forward, df.name)

        for df in sorted(flows, key=_flow_sort_key):
            src_name = guid_to_name.get(df.source_guid, df.source_guid)
            tgt_name = guid_to_name.get(df.target_guid, df.target_guid)
            src_id = mid(src_name)
            tgt_id = mid(tgt_name)
            label = df.name
            lines.append(f'    {src_id} -->|"{label}"| {tgt_id}')

        return lines

    def _mermaid_node(self, el: Element) -> str:
        mid = re.sub(r"[^a-zA-Z0-9_]", "", el.name.replace(" ", "_"))
        if el.generic_type == "GE.EI":
            return f'{mid}["{el.name} (External Interactor)"]'
        elif el.generic_type == "GE.P":
            return f'{mid}[["{el.name} (Process)"]]'
        elif el.generic_type == "GE.DS":
            return f'{mid}[("{el.name} (Data Store)")]'
        else:
            return f'{mid}["{el.name}"]'


# ---------------------------------------------------------------------------
# TM7 Generator — ThreatModel → TM7 XML
# ---------------------------------------------------------------------------


def _xml_escape(text: str) -> str:
    """Escape text for safe embedding in XML character data."""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))


def _splice_section(text: str, tag: str, inner: str) -> str:
    """Replace the content of the first ``<tag …>…</tag>`` (or ``<tag …/>``)."""

    def _repl(m: re.Match) -> str:
        opening = m.group(1)  # e.g. '<Borders xmlns:a="…"'
        # Recover the closing tag name (may have a namespace prefix)
        close_m = re.search(rf"</([a-zA-Z0-9_]*:?{tag})>\s*$", m.group(0))
        close = close_m.group(1) if close_m else tag
        return f"{opening}>{inner}</{close}>"

    pattern = rf"(<(?:[a-zA-Z0-9_]+:)?{tag}(?:\s[^>]*)?)(?:/>|>.*?</(?:[a-zA-Z0-9_]+:)?{tag}>)"
    return re.sub(pattern, _repl, text, count=1, flags=re.DOTALL)


# Map GenericTypeId to DataContractSerializer i:type for stencil shapes
_STENCIL_SHAPE = {
    "GE.EI": "StencilRectangle",
    "GE.P": "StencilEllipse",
    "GE.DS": "StencilParallelLines",
}


def _stencil_xml(guid: str, generic_type: str, type_id: str, name: str,
                 height: int, left: int, top: int, width: int,
                 stroke: int, NS: dict, z_id: str = "") -> str:
    """Build a ``KeyValueOfguidanyType`` XML fragment for a stencil."""
    shape = _STENCIL_SHAPE.get(generic_type, "StencilRectangle")
    zattr = f' z:Id="{z_id}" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/"' if z_id else ""
    return (
        f'<a:KeyValueOfguidanyType xmlns:a="{NS["a"]}">' 
        f"<a:Key>{_xml_escape(guid)}</a:Key>"
        f'<a:Value{zattr} xmlns:i="{NS["i"]}" i:type="{shape}">'
        f'<GenericTypeId xmlns="{NS["abs"]}">{_xml_escape(generic_type)}</GenericTypeId>'
        f'<Guid xmlns="{NS["abs"]}">{_xml_escape(guid)}</Guid>'
        f'<Properties xmlns="{NS["abs"]}" xmlns:b="{NS["a"]}">'
        f'<b:anyType i:type="c:StringDisplayAttribute" xmlns:c="{NS["kb"]}">'
        f"<c:DisplayName>Name</c:DisplayName><c:Name />"
        f'<c:Value i:type="d:string" xmlns:d="{NS["xs"]}">{_xml_escape(name)}</c:Value>'
        f"</b:anyType></Properties>"
        f'<TypeId xmlns="{NS["abs"]}">{_xml_escape(type_id)}</TypeId>'
        f'<Height xmlns="{NS["abs"]}">{height}</Height>'
        f'<Left xmlns="{NS["abs"]}">{left}</Left>'
        f'<StrokeThickness xmlns="{NS["abs"]}">{stroke}</StrokeThickness>'
        f'<Top xmlns="{NS["abs"]}">{top}</Top>'
        f'<Width xmlns="{NS["abs"]}">{width}</Width>'
        f"</a:Value></a:KeyValueOfguidanyType>"
    )


def _border_boundary_xml(guid: str, type_id: str, name: str,
                         height: int, left: int, top: int, width: int,
                         NS: dict, z_id: str = "") -> str:
    """Build a ``KeyValueOfguidanyType`` XML fragment for a BorderBoundary (box)."""
    zattr = f' z:Id="{z_id}" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/"' if z_id else ""
    return (
        f'<a:KeyValueOfguidanyType xmlns:a="{NS["a"]}">'
        f"<a:Key>{_xml_escape(guid)}</a:Key>"
        f'<a:Value{zattr} xmlns:i="{NS["i"]}" i:type="BorderBoundary">'
        f'<GenericTypeId xmlns="{NS["abs"]}">{_BORDER_BOUNDARY_GTYPE}</GenericTypeId>'
        f'<Guid xmlns="{NS["abs"]}">{_xml_escape(guid)}</Guid>'
        f'<Properties xmlns="{NS["abs"]}" xmlns:b="{NS["a"]}">'
        f'<b:anyType i:type="c:HeaderDisplayAttribute" xmlns:c="{NS["kb"]}">'
        f"<c:DisplayName>{_xml_escape(name)}</c:DisplayName><c:Name />"
        f'<c:Value i:nil="true"/>'
        f"</b:anyType>"
        f'<b:anyType i:type="c:StringDisplayAttribute" xmlns:c="{NS["kb"]}">'
        f"<c:DisplayName>Name</c:DisplayName><c:Name />"
        f'<c:Value i:type="d:string" xmlns:d="{NS["xs"]}">{_xml_escape(name)}</c:Value>'
        f"</b:anyType></Properties>"
        f'<TypeId xmlns="{NS["abs"]}">{_xml_escape(type_id)}</TypeId>'
        f'<Height xmlns="{NS["abs"]}">{height}</Height>'
        f'<Left xmlns="{NS["abs"]}">{left}</Left>'
        f'<StrokeDashArray xmlns="{NS["abs"]}">1</StrokeDashArray>'
        f'<StrokeThickness xmlns="{NS["abs"]}">1</StrokeThickness>'
        f'<Top xmlns="{NS["abs"]}">{top}</Top>'
        f'<Width xmlns="{NS["abs"]}">{width}</Width>'
        f"</a:Value></a:KeyValueOfguidanyType>"
    )


def _line_boundary_xml(guid: str, generic_type: str, type_id: str, name: str,
                       NS: dict, z_id: str = "",
                       source_x: int = 297, source_y: int = 10,
                       target_x: int = 294, target_y: int = 306) -> str:
    """Build a ``KeyValueOfguidanyType`` XML fragment for a LineBoundary."""
    zattr = f' z:Id="{z_id}" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/"' if z_id else ""
    nil_guid = "00000000-0000-0000-0000-000000000000"
    handle_x = (source_x + target_x) // 2
    handle_y = (source_y + target_y) // 2
    return (
        f'<a:KeyValueOfguidanyType xmlns:a="{NS["a"]}">' 
        f"<a:Key>{_xml_escape(guid)}</a:Key>"
        f'<a:Value{zattr} xmlns:i="{NS["i"]}" i:type="LineBoundary">'
        f'<GenericTypeId xmlns="{NS["abs"]}">{_xml_escape(generic_type)}</GenericTypeId>'
        f'<Guid xmlns="{NS["abs"]}">{_xml_escape(guid)}</Guid>'
        f'<Properties xmlns="{NS["abs"]}" xmlns:b="{NS["a"]}">'
        f'<b:anyType i:type="c:StringDisplayAttribute" xmlns:c="{NS["kb"]}">'
        f"<c:DisplayName>Name</c:DisplayName><c:Name />"
        f'<c:Value i:type="d:string" xmlns:d="{NS["xs"]}">{_xml_escape(name)}</c:Value>'
        f"</b:anyType></Properties>"
        f'<TypeId xmlns="{NS["abs"]}">{_xml_escape(type_id)}</TypeId>'
        f'<HandleX xmlns="{NS["abs"]}">{handle_x}</HandleX>'
        f'<HandleY xmlns="{NS["abs"]}">{handle_y}</HandleY>'
        f'<PortSource xmlns="{NS["abs"]}">None</PortSource>'
        f'<PortTarget xmlns="{NS["abs"]}">None</PortTarget>'
        f'<SourceGuid xmlns="{NS["abs"]}">{nil_guid}</SourceGuid>'
        f'<SourceX xmlns="{NS["abs"]}">{source_x}</SourceX>'
        f'<SourceY xmlns="{NS["abs"]}">{source_y}</SourceY>'
        f'<TargetGuid xmlns="{NS["abs"]}">{nil_guid}</TargetGuid>'
        f'<TargetX xmlns="{NS["abs"]}">{target_x}</TargetX>'
        f'<TargetY xmlns="{NS["abs"]}">{target_y}</TargetY>'
        f"</a:Value></a:KeyValueOfguidanyType>"
    )


class TM7Generator:
    """Generate a TM7 XML file from a ThreatModel.

    Optionally uses a template TM7 to preserve the KnowledgeBase section.

    Because .NET DataContractSerializer embeds namespace-prefixed values inside
    ``xsi:type`` attributes, round-tripping through Python's ElementTree
    corrupts those references.  The ``write()`` / ``generate_text()`` methods
    use raw-text splicing to avoid this problem when a template is available.
    """

    # Default template (empty TM7 created by TMT) shipped alongside this script
    _DEFAULT_TEMPLATE_PATH = Path(__file__).resolve().parent / "references" / "default_template.tm7"

    def __init__(self, template_path: Optional[str | Path] = None):
        self.template_tree = None
        self._template_path: Optional[Path] = None
        path = template_path or (
            self._DEFAULT_TEMPLATE_PATH if self._DEFAULT_TEMPLATE_PATH.exists() else None
        )
        if path:
            self._template_path = Path(path)
            self.template_tree = ET.parse(path)

    def generate(self, model: ThreatModel) -> ET.ElementTree:
        if self.template_tree:
            root = copy.deepcopy(self.template_tree.getroot())
        else:
            root = self._create_skeleton()

        self._set_meta(root, model.meta)
        self._set_drawing_surface(root, model)
        self._set_threats(root, model)

        return ET.ElementTree(root)

    # ------------------------------------------------------------------
    # Template-safe output (raw-text splicing avoids namespace corruption)
    # ------------------------------------------------------------------

    def write(self, model: ThreatModel, output_path: str | Path) -> None:
        """Write TM7 to *output_path*, using raw-text splicing when a template is available."""
        Path(output_path).write_bytes(self.generate_text(model).encode("utf-8"))

    def generate_text(self, model: ThreatModel) -> str:
        """Return TM7 XML string, using raw-text splicing when a template is available."""
        if self._template_path:
            return self._generate_from_template(model)
        tree = self.generate(model)
        return ET.tostring(tree.getroot(), encoding="unicode")

    def _generate_from_template(self, model: ThreatModel) -> str:
        text = self._template_path.read_bytes().decode("utf-8")

        # --- Metadata ---
        meta_fields = {
            "ThreatModelName": model.meta.name,
            "Owner": model.meta.owner,
            "Reviewer": model.meta.reviewer,
            "HighLevelSystemDescription": model.meta.description,
            "Assumptions": model.meta.assumptions,
            "ExternalDependencies": model.meta.external_dependencies,
            "Contributors": model.meta.contributors,
        }
        for tag, value in meta_fields.items():
            text = re.sub(
                rf"(<{tag}(?:\s[^>]*)?)(?:/>|>(.*?)</{tag}>)",
                lambda m, t=tag, v=value: f"{m.group(1)}>{_xml_escape(v)}</{t}>",
                text, count=1,
            )

        diagrams = model.diagrams if model.diagrams else [Diagram()]

        # Find the max z:Id in the template so we don't collide with
        # KnowledgeBase or other template-level z:Id values.
        existing_ids = [int(m.group(1)) for m in re.finditer(r'z:Id="i(\d+)"', text)]
        z_start = max(existing_ids, default=2) + 1

        if len(diagrams) <= 1:
            # Single diagram: splice into the existing DrawingSurfaceModel
            diag = diagrams[0]
            borders_xml, el_positions, next_z = self._borders_xml(
                diag.elements, z_id_start=z_start, boundaries=diag.boundaries)
            text = _splice_section(text, "Borders", borders_xml)
            text = _splice_section(text, "Lines",
                                   self._lines_xml(diag.elements, diag.flows,
                                                   diag.boundaries, el_positions,
                                                   z_id_start=next_z))
            if diag.name:
                text = _splice_section(text, "Header", _xml_escape(diag.name))
        else:
            # Multi-diagram: build all DrawingSurfaceModel blocks and
            # replace the DrawingSurfaceList content.
            dsm_parts: list[str] = []
            z_id = z_start
            for i, diag in enumerate(diagrams):
                dsm_z_id = f"i{z_id}"
                z_id += 1
                borders_xml, el_positions, z_id = self._borders_xml(
                    diag.elements, z_id_start=z_id, boundaries=diag.boundaries)
                lines_xml = self._lines_xml(diag.elements, diag.flows,
                                            diag.boundaries, el_positions,
                                            z_id_start=z_id)
                # Count line items: flows + empty boundaries only
                empty_tb = sum(1 for tb in diag.boundaries if not tb.elements)
                z_id += len(diag.flows) + empty_tb
                dsm_parts.append(self._dsm_xml(diag, dsm_z_id, borders_xml, lines_xml))
            text = _splice_section(text, "DrawingSurfaceList", "".join(dsm_parts))

        # --- ThreatInstances ---
        ds_m = re.search(r"<Guid[^>]*>([0-9a-fA-F-]+)</Guid>", text)
        ds_guid = ds_m.group(1) if ds_m else str(uuid.uuid4())
        text = _splice_section(text, "ThreatInstances", self._threats_xml(model, ds_guid))

        return text

    @staticmethod
    def _dsm_xml(diag: 'Diagram', z_id: str, borders_xml: str, lines_xml: str) -> str:
        """Build a complete DrawingSurfaceModel XML block."""
        dsm_guid = diag.guid or str(uuid.uuid4())
        name = _xml_escape(diag.name or "Diagram")
        ns_abs = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts"
        ns_arr = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
        ns_i = "http://www.w3.org/2001/XMLSchema-instance"
        ns_kb = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
        ns_xs = "http://www.w3.org/2001/XMLSchema"
        ns_z = "http://schemas.microsoft.com/2003/10/Serialization/"
        return (
            f'<DrawingSurfaceModel z:Id="{z_id}" xmlns:z="{ns_z}">'
            f'<GenericTypeId xmlns="{ns_abs}">DRAWINGSURFACE</GenericTypeId>'
            f'<Guid xmlns="{ns_abs}">{dsm_guid}</Guid>'
            f'<Properties xmlns="{ns_abs}" xmlns:a="{ns_arr}">'
            f'<a:anyType i:type="b:StringDisplayAttribute" xmlns:i="{ns_i}" xmlns:b="{ns_kb}">'
            f'<b:DisplayName>Name</b:DisplayName><b:Name>Name</b:Name>'
            f'<b:Value i:type="c:string" xmlns:c="{ns_xs}">{name}</b:Value>'
            f'</a:anyType></Properties>'
            f'<TypeId xmlns="{ns_abs}">DRAWINGSURFACE</TypeId>'
            f'<Borders xmlns:a="{ns_arr}">{borders_xml}</Borders>'
            f'<Header>{name}</Header>'
            f'<Lines xmlns:a="{ns_arr}">{lines_xml}</Lines>'
            f'<Zoom>1</Zoom>'
            f'</DrawingSurfaceModel>'
        )

    # --- fragment builders (self-contained namespace declarations) ---

    @staticmethod
    def _borders_xml(elements: list[Element], z_id_start: int = 3,
                     boundaries: list['TrustBoundary'] | None = None) -> tuple[str, dict, int]:
        """Return (xml_fragment, {guid: (left, top, width, height)}, next_z_id).

        Elements are laid out in columns grouped by trust boundary membership.
        Boundaries with elements are emitted as BorderBoundary boxes that
        geometrically contain their member elements.
        """
        if not elements and not boundaries:
            return "", {}, z_id_start
        boundaries = boundaries or []
        NS = {
            "a": "http://schemas.microsoft.com/2003/10/Serialization/Arrays",
            "abs": "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts",
            "kb": "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase",
            "i": "http://www.w3.org/2001/XMLSchema-instance",
            "xs": "http://www.w3.org/2001/XMLSchema",
        }

        # --- Group elements by boundary membership ---
        in_boundary: dict[str, str] = {}  # element name -> boundary name
        for tb in boundaries:
            for ename in tb.elements:
                in_boundary[ename] = tb.name

        # Ordered groups: first boundaries (in order), then ungrouped
        groups: list[tuple[str | None, list[Element]]] = []
        ungrouped: list[Element] = []
        tb_groups: dict[str, list[Element]] = {tb.name: [] for tb in boundaries if tb.elements}
        for el in elements:
            bname = in_boundary.get(el.name)
            if bname and bname in tb_groups:
                tb_groups[bname].append(el)
            else:
                ungrouped.append(el)

        # Ungrouped first (leftmost), then boundary groups in order
        if ungrouped:
            groups.append((None, ungrouped))
        for tb in boundaries:
            if tb.elements and tb.name in tb_groups and tb_groups[tb.name]:
                groups.append((tb.name, tb_groups[tb.name]))

        # --- 2D layout: bounded groups are vertical columns,
        #     ungrouped elements spread horizontally ---
        PAD = 30       # padding inside border boundary box
        COL_GAP = 100  # gap between columns
        ROW_GAP = 30   # gap between elements within a column
        START_X = 50
        START_Y = 50

        parts: list[str] = []
        positions: dict[str, tuple[int, int, int, int]] = {}
        boundary_rects: dict[str, tuple[int, int, int, int]] = {}  # name -> (l,t,w,h)
        z_id = z_id_start
        x_cursor = START_X

        for group_name, group_els in groups:
            has_boundary = group_name is not None

            if has_boundary:
                # Bounded group: stack elements vertically inside the box
                col_x = x_cursor + PAD
                col_y = START_Y + PAD
                max_w = 0
                y_cursor = col_y
                for el in group_els:
                    w = int(el.width) if el.width else 100
                    h = int(el.height) if el.height else 100
                    parts.append(_stencil_xml(el.guid, el.generic_type,
                                              el.type_id or el.generic_type,
                                              el.name, h, col_x, y_cursor, w, 1, NS,
                                              z_id=f"i{z_id}"))
                    positions[el.guid] = (col_x, y_cursor, w, h)
                    max_w = max(max_w, w)
                    y_cursor += h + ROW_GAP
                    z_id += 1
                box_left = x_cursor
                box_top = START_Y
                box_width = max_w + 2 * PAD
                box_height = (y_cursor - ROW_GAP) - START_Y + PAD
                boundary_rects[group_name] = (box_left, box_top, box_width, box_height)
                x_cursor = box_left + box_width + COL_GAP
            else:
                # Ungrouped elements: lay out horizontally at the same Y level
                for el in group_els:
                    w = int(el.width) if el.width else 100
                    h = int(el.height) if el.height else 100
                    parts.append(_stencil_xml(el.guid, el.generic_type,
                                              el.type_id or el.generic_type,
                                              el.name, h, x_cursor, START_Y, w, 1, NS,
                                              z_id=f"i{z_id}"))
                    positions[el.guid] = (x_cursor, START_Y, w, h)
                    x_cursor += w + COL_GAP
                    z_id += 1

        # Emit border boundaries
        tb_by_name = {tb.name: tb for tb in boundaries}
        for bname, (bl, bt, bw, bh) in boundary_rects.items():
            tb = tb_by_name[bname]
            parts.append(_border_boundary_xml(
                tb.guid, _BORDER_BOUNDARY_GTYPE,
                bname, bh, bl, bt, bw, NS,
                z_id=f"i{z_id}"))
            z_id += 1

        return "".join(parts), positions, z_id

    @staticmethod
    def _lines_xml(elements: list[Element], flows: list[DataFlow],
                   boundaries: list[TrustBoundary], el_positions: dict,
                   z_id_start: int = 3) -> str:
        if not flows and not boundaries:
            return ""
        name_to_guid = {e.name: e.guid for e in elements}
        NS = {
            "a": "http://schemas.microsoft.com/2003/10/Serialization/Arrays",
            "abs": "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts",
            "kb": "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase",
            "i": "http://www.w3.org/2001/XMLSchema-instance",
            "xs": "http://www.w3.org/2001/XMLSchema",
        }
        parts: list[str] = []
        z_id = z_id_start

        # Build a set of element-pair keys to detect bidirectional flows.
        # For each pair (A,B), track which flows we've seen so we can offset
        # the handle of the second flow in the opposite direction.
        pair_seen: dict[tuple[str, str], int] = {}  # (min_guid, max_guid) -> count
        CURVE_OFFSET = 50  # pixels above/below the straight line for curves

        for df in flows:
            sg = name_to_guid.get(df.source_guid, df.source_guid)
            tg = name_to_guid.get(df.target_guid, df.target_guid)
            df.source_guid, df.target_guid = sg, tg
            # Compute connector coordinates from element positions
            sx, sy, sw, sh = el_positions.get(sg, (0, 100, 100, 100))
            tx, ty, tw, th = el_positions.get(tg, (250, 100, 100, 100))
            src_cy = sy + sh // 2
            tgt_cy = ty + th // 2
            # Direction-aware: source-right→target-left when source is left
            # of target, otherwise source-left→target-right.
            if sx <= tx:
                source_x = sx + sw   # right edge of source
                source_y = src_cy
                target_x = tx        # left edge of target
                target_y = tgt_cy
                port_source, port_target = "East", "West"
            else:
                source_x = sx        # left edge of source
                source_y = src_cy
                target_x = tx + tw   # right edge of target
                target_y = tgt_cy
                port_source, port_target = "West", "East"

            # Handle: midpoint of the connector line, with vertical offset
            # for bidirectional pairs so the curves bow in opposite directions.
            handle_x = (source_x + target_x) // 2
            handle_y = (source_y + target_y) // 2
            pair_key = (min(sg, tg), max(sg, tg))
            pair_idx = pair_seen.get(pair_key, 0)
            pair_seen[pair_key] = pair_idx + 1
            if pair_idx == 0:
                # First flow in pair: curve upward
                handle_y -= CURVE_OFFSET
            else:
                # Second flow in pair: curve downward
                handle_y += CURVE_OFFSET

            parts.append(
                f'<a:KeyValueOfguidanyType xmlns:a="{NS["a"]}">'
                f"<a:Key>{_xml_escape(df.guid)}</a:Key>"
                f'<a:Value z:Id="i{z_id}" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/" xmlns:i="{NS["i"]}" i:type="Connector">'
                f'<GenericTypeId xmlns="{NS["abs"]}">{_xml_escape(df.generic_type)}</GenericTypeId>'
                f'<Guid xmlns="{NS["abs"]}">{_xml_escape(df.guid)}</Guid>'
                f'<Properties xmlns="{NS["abs"]}" xmlns:b="{NS["a"]}">'
                f'<b:anyType i:type="c:StringDisplayAttribute" xmlns:c="{NS["kb"]}">'
                f"<c:DisplayName>Name</c:DisplayName><c:Name />"
                f'<c:Value i:type="d:string" xmlns:d="{NS["xs"]}">{_xml_escape(df.name)}</c:Value>'
                f"</b:anyType></Properties>"
                f'<TypeId xmlns="{NS["abs"]}">{_xml_escape(df.type_id or "GE.DF")}</TypeId>'
                f'<HandleX xmlns="{NS["abs"]}">{handle_x}</HandleX>'
                f'<HandleY xmlns="{NS["abs"]}">{handle_y}</HandleY>'
                f'<PortSource xmlns="{NS["abs"]}">{port_source}</PortSource>'
                f'<PortTarget xmlns="{NS["abs"]}">{port_target}</PortTarget>'
                f'<SourceGuid xmlns="{NS["abs"]}">{_xml_escape(sg)}</SourceGuid>'
                f'<SourceX xmlns="{NS["abs"]}">{source_x}</SourceX>'
                f'<SourceY xmlns="{NS["abs"]}">{source_y}</SourceY>'
                f'<TargetGuid xmlns="{NS["abs"]}">{_xml_escape(tg)}</TargetGuid>'
                f'<TargetX xmlns="{NS["abs"]}">{target_x}</TargetX>'
                f'<TargetY xmlns="{NS["abs"]}">{target_y}</TargetY>'
                f"</a:Value></a:KeyValueOfguidanyType>"
            )
            z_id += 1
        # Trust boundaries as LineBoundary entries — only for boundaries
        # without elements (populated boundaries are emitted as BorderBoundary
        # in Borders).
        if el_positions:
            all_tops = [t for _, t, _, _ in el_positions.values()]
            all_bottoms = [t + h for _, t, _, h in el_positions.values()]
            tb_min_y = min(all_tops) - 20
            tb_max_y = max(all_bottoms) + 20
        else:
            tb_min_y, tb_max_y = 10, 306
        tb_x_offset = 0
        for tb in boundaries:
            if tb.elements:
                continue  # already in Borders as BorderBoundary
            tb_generic = "GE.TB.L" if tb.generic_type == "GE.TB" else tb.generic_type
            # Place boundary line between elements; shift each boundary right
            tb_x = 270 + tb_x_offset
            tb_x_offset += 250
            parts.append(_line_boundary_xml(
                tb.guid, tb_generic, tb_generic,
                tb.name, NS, z_id=f"i{z_id}",
                source_x=tb_x, source_y=tb_min_y,
                target_x=tb_x, target_y=tb_max_y))
            z_id += 1
        return "".join(parts)

    @staticmethod
    def _threats_xml(model: ThreatModel, ds_guid: str) -> str:
        if not model.threats:
            return ""
        name_to_guid = {e.name: e.guid for e in model.elements}
        flow_name_to_guid = {f.name: f.guid for f in model.flows}
        now = datetime.now(timezone.utc).isoformat()
        ns_a = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
        ns_kb = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
        ns_i = "http://www.w3.org/2001/XMLSchema-instance"
        parts: list[str] = []
        nil_guid = "00000000-0000-0000-0000-000000000000"
        for idx, t in enumerate(model.threats, 1):
            sg = t.source_guid or name_to_guid.get(t.source, nil_guid)
            tg = t.target_guid or name_to_guid.get(t.target, nil_guid)
            fg = t.flow_guid or flow_name_to_guid.get(t.flow, nil_guid)
            tid = t.id or str(idx)
            ik = t.interaction_key or f"{sg}:{fg}:{tg}"
            ck = f"{tid}{sg}{fg}{tg}"
            cat = STRIDE_REVERSE.get(t.category, t.category)
            sv = STATE_MAP_REVERSE.get(t.state, t.state)

            def _kv(k: str, v: str) -> str:
                return (f'<a:KeyValueOfstringstring xmlns:a="{ns_a}">'
                        f"<a:Key>{_xml_escape(k)}</a:Key>"
                        f"<a:Value>{_xml_escape(v)}</a:Value>"
                        f"</a:KeyValueOfstringstring>")

            p = [_kv("Title", t.title),
                 _kv("UserThreatCategory", STRIDE_CATEGORIES.get(cat, t.category)),
                 _kv("UserThreatDescription", t.description),
                 _kv("Priority", t.priority),
                 _kv("f9e02b87-2914-407e-bd11-97353ef43162", t.risk)]
            if t.mitigation:
                p.append(_kv("44490cdf-6399-4291-9bde-03dca6f03c11", t.mitigation))

            parts.append(
                f'<a:KeyValueOfstringThreatpc_P0_PhOB xmlns:a="{ns_a}">'
                f"<a:Key>{_xml_escape(ck)}</a:Key>"
                f'<a:Value xmlns:b="{ns_kb}">'
                f"<b:ChangedBy>{_xml_escape(t.changed_by or 'AI Agent')}</b:ChangedBy>"
                f"<b:DrawingSurfaceGuid>{_xml_escape(t.drawing_surface_guid or ds_guid)}</b:DrawingSurfaceGuid>"
                f"<b:FlowGuid>{_xml_escape(fg)}</b:FlowGuid>"
                f"<b:Id>{_xml_escape(tid)}</b:Id>"
                f"<b:InteractionKey>{_xml_escape(ik)}</b:InteractionKey>"
                f'<b:InteractionString xmlns:i="{ns_i}" i:nil="true" />'
                f"<b:ModifiedAt>{_xml_escape(t.modified_at or now)}</b:ModifiedAt>"
                f"<b:Priority>{_xml_escape(t.priority)}</b:Priority>"
                f"<b:Properties>{''.join(p)}</b:Properties>"
                f"<b:SourceGuid>{_xml_escape(sg)}</b:SourceGuid>"
                f"<b:State>{_xml_escape(sv)}</b:State>"
                f'<b:StateInformation xmlns:i="{ns_i}" i:nil="true" />'
                f"<b:TargetGuid>{_xml_escape(tg)}</b:TargetGuid>"
                f"<b:TypeId>{_xml_escape(t.threat_type_id or tid)}</b:TypeId>"
                f"</a:Value></a:KeyValueOfstringThreatpc_P0_PhOB>"
            )
        return "".join(parts)

    def _create_skeleton(self) -> ET.Element:
        """Fallback skeleton when no template is available."""
        root = ET.Element(_tag(NS_TM, "ThreatModel"))
        ET.SubElement(root, _tag(NS_TM, "DrawingSurfaceList"))
        ET.SubElement(root, _tag(NS_TM, "MetaInformation"))
        ET.SubElement(root, _tag(NS_TM, "Notes"))
        ET.SubElement(root, _tag(NS_TM, "ThreatInstances"))
        el = ET.SubElement(root, _tag(NS_TM, "ThreatGenerationEnabled"))
        el.text = "true"
        ET.SubElement(root, _tag(NS_TM, "Validations"))
        ver = ET.SubElement(root, _tag(NS_TM, "Version"))
        ver.text = "2.0"
        profile = ET.SubElement(root, _tag(NS_TM, "Profile"))
        ET.SubElement(profile, _tag(NS_TM, "PromptedKb"))
        return root

    def _set_meta(self, root: ET.Element, meta: ThreatModelMeta):
        meta_el = root.find(_tag(NS_TM, "MetaInformation"))
        if meta_el is None:
            meta_el = ET.SubElement(root, _tag(NS_TM, "MetaInformation"))

        self._set_child_text(meta_el, NS_TM, "ThreatModelName", meta.name)
        self._set_child_text(meta_el, NS_TM, "Owner", meta.owner)
        self._set_child_text(meta_el, NS_TM, "Reviewer", meta.reviewer)
        self._set_child_text(meta_el, NS_TM, "HighLevelSystemDescription", meta.description)
        self._set_child_text(meta_el, NS_TM, "Assumptions", meta.assumptions)
        self._set_child_text(meta_el, NS_TM, "ExternalDependencies", meta.external_dependencies)
        self._set_child_text(meta_el, NS_TM, "Contributors", meta.contributors)

    def _set_drawing_surface(self, root: ET.Element, model: ThreatModel):
        ds_list = root.find(_tag(NS_TM, "DrawingSurfaceList"))
        if ds_list is None:
            ds_list = ET.SubElement(root, _tag(NS_TM, "DrawingSurfaceList"))

        # Reuse existing DrawingSurfaceModel from template (preserves z:Id and
        # other DataContract serialisation attributes), or create a new one.
        ds = ds_list.find(_tag(NS_TM, "DrawingSurfaceModel"))
        if ds is None:
            ds = ET.SubElement(ds_list, _tag(NS_TM, "DrawingSurfaceModel"))

        ds_guid_el = ds.find(_tag(NS_ABS, "Guid"))
        if ds_guid_el is not None:
            ds_guid = ds_guid_el.text
        else:
            ds_guid = str(uuid.uuid4())

        # Update Borders — clear and repopulate with model elements
        borders = ds.find(_tag(NS_TM, "Borders"))
        if borders is None:
            borders = ET.SubElement(ds, _tag(NS_TM, "Borders"))
        else:
            for child in list(borders):
                borders.remove(child)
        self._add_elements_to_borders(borders, model)

        # Update Lines — clear and repopulate with model flows
        lines = ds.find(_tag(NS_TM, "Lines"))
        if lines is None:
            lines = ET.SubElement(ds, _tag(NS_TM, "Lines"))
        else:
            for child in list(lines):
                lines.remove(child)
        self._add_flows_to_lines(lines, model)

        # Store surface guid for threats
        model._drawing_surface_guid = ds_guid

    def _add_elements_to_borders(self, borders: ET.Element, model: ThreatModel):
        x_pos = 50.0
        for el in model.elements:
            kv = ET.SubElement(borders, _tag(NS_ARR, "KeyValueOfguidanyType"))
            key = ET.SubElement(kv, _tag(NS_ARR, "Key"))
            key.text = el.guid

            val = ET.SubElement(kv, _tag(NS_ARR, "Value"))
            val.set(f"{{{NS_XSI}}}type", "StencilRectangle")

            self._add_child(val, NS_ABS, "GenericTypeId", el.generic_type)
            self._add_child(val, NS_ABS, "Guid", el.guid)

            # Properties
            props = ET.SubElement(val, _tag(NS_ABS, "Properties"))
            self._add_string_prop(props, "Name", "", el.name)

            self._add_child(val, NS_ABS, "TypeId", el.type_id or el.generic_type)
            self._add_child(val, NS_ABS, "Height", str(int(el.height)))
            self._add_child(val, NS_ABS, "Left", str(int(x_pos)))
            self._add_child(val, NS_ABS, "StrokeThickness", "1")
            self._add_child(val, NS_ABS, "Top", "100")
            self._add_child(val, NS_ABS, "Width", str(int(el.width)))

            x_pos += 250.0

        # Trust boundaries
        for tb in model.boundaries:
            kv = ET.SubElement(borders, _tag(NS_ARR, "KeyValueOfguidanyType"))
            key = ET.SubElement(kv, _tag(NS_ARR, "Key"))
            key.text = tb.guid

            val = ET.SubElement(kv, _tag(NS_ARR, "Value"))
            val.set(f"{{{NS_XSI}}}type", "StencilRectangle")

            self._add_child(val, NS_ABS, "GenericTypeId", tb.generic_type)
            self._add_child(val, NS_ABS, "Guid", tb.guid)

            props = ET.SubElement(val, _tag(NS_ABS, "Properties"))
            self._add_string_prop(props, "Name", "", tb.name)

            self._add_child(val, NS_ABS, "TypeId", tb.generic_type)
            self._add_child(val, NS_ABS, "Height", "300")
            self._add_child(val, NS_ABS, "Left", "10")
            self._add_child(val, NS_ABS, "StrokeThickness", "2")
            self._add_child(val, NS_ABS, "Top", "10")
            self._add_child(val, NS_ABS, "Width", "800")

    def _add_flows_to_lines(self, lines: ET.Element, model: ThreatModel):
        name_to_guid = {e.name: e.guid for e in model.elements}

        for df in model.flows:
            # Resolve names to guids if needed
            src_guid = df.source_guid
            tgt_guid = df.target_guid
            if src_guid in name_to_guid:
                src_guid = name_to_guid[src_guid]
                df.source_guid = src_guid
            if tgt_guid in name_to_guid:
                tgt_guid = name_to_guid[tgt_guid]
                df.target_guid = tgt_guid

            kv = ET.SubElement(lines, _tag(NS_ARR, "KeyValueOfguidanyType"))
            key = ET.SubElement(kv, _tag(NS_ARR, "Key"))
            key.text = df.guid

            val = ET.SubElement(kv, _tag(NS_ARR, "Value"))
            val.set(f"{{{NS_XSI}}}type", "Connector")

            self._add_child(val, NS_ABS, "GenericTypeId", df.generic_type)
            self._add_child(val, NS_ABS, "Guid", df.guid)

            props = ET.SubElement(val, _tag(NS_ABS, "Properties"))
            self._add_string_prop(props, "Name", "", df.name)

            self._add_child(val, NS_ABS, "TypeId", df.type_id or "GE.DF")
            self._add_child(val, NS_ABS, "SourceGuid", src_guid)
            self._add_child(val, NS_ABS, "TargetGuid", tgt_guid)

    def _set_threats(self, root: ET.Element, model: ThreatModel):
        ti_root = root.find(_tag(NS_TM, "ThreatInstances"))
        if ti_root is None:
            ti_root = ET.SubElement(root, _tag(NS_TM, "ThreatInstances"))

        # Clear existing
        for child in list(ti_root):
            ti_root.remove(child)

        name_to_guid = {e.name: e.guid for e in model.elements}
        flow_name_to_guid = {f.name: f.guid for f in model.flows}
        ds_guid = getattr(model, "_drawing_surface_guid", str(uuid.uuid4()))
        now = datetime.now(timezone.utc).isoformat()

        for i, t in enumerate(model.threats, 1):
            src_guid = t.source_guid or name_to_guid.get(t.source, "")
            tgt_guid = t.target_guid or name_to_guid.get(t.target, "")
            flow_guid = t.flow_guid or flow_name_to_guid.get(t.flow, "")

            threat_id = t.id or str(i)
            interaction_key = t.interaction_key or f"{src_guid}:{flow_guid}:{tgt_guid}"
            composite_key = f"{threat_id}{src_guid}{flow_guid}{tgt_guid}"

            kv = ET.SubElement(ti_root, _tag(NS_ARR, "KeyValueOfstringThreatpc_P0_PhOB"))
            key = ET.SubElement(kv, _tag(NS_ARR, "Key"))
            key.text = composite_key

            val = ET.SubElement(kv, _tag(NS_ARR, "Value"))

            self._add_child(val, NS_KB, "ChangedBy", t.changed_by or "AI Agent")
            self._add_child(val, NS_KB, "DrawingSurfaceGuid", t.drawing_surface_guid or ds_guid)
            self._add_child(val, NS_KB, "FlowGuid", flow_guid)
            self._add_child(val, NS_KB, "Id", threat_id)
            self._add_child(val, NS_KB, "InteractionKey", interaction_key)

            ik_str = ET.SubElement(val, _tag(NS_KB, "InteractionString"))
            ik_str.set(f"{{{NS_XSI}}}nil", "true")

            self._add_child(val, NS_KB, "ModifiedAt", t.modified_at or now)
            self._add_child(val, NS_KB, "Priority", t.priority)

            # Properties
            props = ET.SubElement(val, _tag(NS_KB, "Properties"))
            self._add_threat_prop(props, "Title", t.title)

            # Map category
            cat = t.category
            if cat in STRIDE_REVERSE:
                cat_code = STRIDE_REVERSE[cat]
            else:
                cat_code = cat
            self._add_threat_prop(props, "UserThreatCategory", STRIDE_CATEGORIES.get(cat_code, cat))
            self._add_threat_prop(props, "UserThreatDescription", t.description)
            self._add_threat_prop(props, "Priority", t.priority)
            self._add_threat_prop(props, "f9e02b87-2914-407e-bd11-97353ef43162", t.risk)
            if t.mitigation:
                self._add_threat_prop(props, "44490cdf-6399-4291-9bde-03dca6f03c11", t.mitigation)

            self._add_child(val, NS_KB, "SourceGuid", src_guid)

            state_val = STATE_MAP_REVERSE.get(t.state, t.state)
            self._add_child(val, NS_KB, "State", state_val)

            si = ET.SubElement(val, _tag(NS_KB, "StateInformation"))
            si.set(f"{{{NS_XSI}}}nil", "true")

            self._add_child(val, NS_KB, "TargetGuid", tgt_guid)
            self._add_child(val, NS_KB, "TypeId", t.threat_type_id or threat_id)

    # --- XML helpers ---

    def _add_child(self, parent: ET.Element, ns: str, tag: str, text: str):
        el = ET.SubElement(parent, _tag(ns, tag))
        el.text = text

    def _set_child_text(self, parent: ET.Element, ns: str, tag: str, text: str):
        el = parent.find(_tag(ns, tag))
        if el is None:
            el = ET.SubElement(parent, _tag(ns, tag))
        el.text = text

    def _add_string_prop(self, props: ET.Element, display_name: str, name: str, value: str):
        at = ET.SubElement(props, _tag(NS_ARR, "anyType"))
        at.set(f"{{{NS_XSI}}}type", "b:StringDisplayAttribute")
        dn = ET.SubElement(at, _tag(NS_KB, "DisplayName"))
        dn.text = display_name
        n = ET.SubElement(at, _tag(NS_KB, "Name"))
        n.text = name
        v = ET.SubElement(at, _tag(NS_KB, "Value"))
        v.set(f"{{{NS_XSI}}}type", "c:string")
        v.text = value

    def _add_threat_prop(self, props: ET.Element, key: str, value: str):
        kv = ET.SubElement(props, _tag(NS_ARR, "KeyValueOfstringstring"))
        k = ET.SubElement(kv, _tag(NS_ARR, "Key"))
        k.text = key
        v = ET.SubElement(kv, _tag(NS_ARR, "Value"))
        v.text = value


# ---------------------------------------------------------------------------
# Summary generator
# ---------------------------------------------------------------------------


def generate_summary(model: ThreatModel) -> dict:
    """Generate a concise JSON summary of a threat model."""
    state_counts = {}
    category_counts = {}
    for t in model.threats:
        state_counts[t.state] = state_counts.get(t.state, 0) + 1
        category_counts[t.category] = category_counts.get(t.category, 0) + 1

    return {
        "name": model.meta.name,
        "owner": model.meta.owner,
        "elements": len(model.elements),
        "data_flows": len(model.flows),
        "trust_boundaries": len(model.boundaries),
        "threats": {
            "total": len(model.threats),
            "by_state": state_counts,
            "by_category": category_counts,
        },
        "element_list": [
            {"name": e.name, "type": e.generic_type} for e in model.elements
        ],
        "threat_list": [
            {"id": t.id, "title": t.title, "state": t.state, "priority": t.priority}
            for t in model.threats
        ],
    }


# ---------------------------------------------------------------------------
# Threat update merger
# ---------------------------------------------------------------------------


def update_threats_from_markdown(
    tm7_path: str | Path, md_path: str | Path, output_path: str | Path
):
    """Update threat states/mitigations in TM7 from a reviewed Markdown file."""
    # Parse both
    tm7_model = TM7Parser(tm7_path).parse()
    md_model = MarkdownParser(md_path).parse()

    # Build lookup from markdown threats by title
    md_threats_by_title = {t.title: t for t in md_model.threats}
    md_threats_by_id = {t.id: t for t in md_model.threats if t.id}

    updated = 0
    for t in tm7_model.threats:
        md_t = md_threats_by_id.get(t.id) or md_threats_by_title.get(t.title)
        if md_t:
            t.state = md_t.state
            t.priority = md_t.priority or t.priority
            t.risk = md_t.risk or t.risk
            t.mitigation = md_t.mitigation or t.mitigation
            t.justification = md_t.justification or t.justification
            updated += 1

    # Regenerate TM7 using original as template
    gen = TM7Generator(template_path=tm7_path)
    tree = gen.generate(tm7_model)
    tree.write(str(output_path), encoding="unicode", xml_declaration=True)
    return updated


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_markdown(md_path: str | Path) -> list[str]:
    """Validate a Markdown threat model for completeness."""
    model = MarkdownParser(md_path).parse()
    issues = []

    if not model.meta.name:
        issues.append("Missing threat model name (H1 heading)")
    if not model.meta.owner:
        issues.append("Missing owner in Metadata")
    if not model.elements:
        issues.append("No elements defined in Elements table")
    if not model.flows:
        issues.append("No data flows defined in Data Flows table")
    if not model.threats:
        issues.append("No threats defined in Threats section")

    element_names = {e.name for e in model.elements}
    for df in model.flows:
        if df.source_guid not in element_names:
            issues.append(f"Data flow '{df.name}' references unknown source '{df.source_guid}'")
        if df.target_guid not in element_names:
            issues.append(f"Data flow '{df.name}' references unknown target '{df.target_guid}'")

    for t in model.threats:
        if not t.title:
            issues.append(f"Threat {t.id} has no title")
        if not t.category:
            issues.append(f"Threat '{t.title}' has no STRIDE category")
        if t.state in ("Not Applicable",) and not t.justification:
            issues.append(f"Threat '{t.title}' marked Not Applicable without justification")
        if t.state == "Mitigated" and not t.mitigation:
            issues.append(f"Threat '{t.title}' marked Mitigated without mitigation description")

    return issues


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_parse(args):
    model = TM7Parser(args.input).parse()
    md = MarkdownGenerator().generate(model)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"Written to {args.output}")
    else:
        print(md)


def cmd_generate(args):
    model = MarkdownParser(args.input).parse()
    gen = TM7Generator(template_path=args.template)
    output = args.output or str(Path(args.input).with_suffix(".tm7"))
    gen.write(model, output)
    print(f"Written to {output}")


def cmd_summary(args):
    model = TM7Parser(args.input).parse()
    summary = generate_summary(model)
    text = json.dumps(summary, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text, encoding="utf-8")
        print(f"Written to {args.output_file}")
    else:
        print(text)


def cmd_update_threats(args):
    count = update_threats_from_markdown(args.tm7, args.markdown, args.output)
    print(f"Updated {count} threats. Written to {args.output}")


def cmd_validate(args):
    issues = validate_markdown(args.input)
    if issues:
        print(f"Found {len(issues)} issue(s):")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    else:
        print("Validation passed — no issues found.")


def main():
    parser = argparse.ArgumentParser(
        description="Threat Modeling CLI — Convert between Markdown and TM7 formats."
    )
    subs = parser.add_subparsers(dest="command", required=True)

    # parse
    p_parse = subs.add_parser("parse", help="Parse a TM7 file to Markdown")
    p_parse.add_argument("--input", required=True, help="Input TM7 file")
    p_parse.add_argument("--output", help="Output Markdown file (default: stdout)")
    p_parse.set_defaults(func=cmd_parse)

    # generate
    p_gen = subs.add_parser("generate", help="Generate a TM7 from Markdown")
    p_gen.add_argument("--input", required=True, help="Input Markdown file")
    p_gen.add_argument("--output", help="Output TM7 file")
    p_gen.add_argument("--template", help="Template TM7 (preserves KnowledgeBase)")
    p_gen.set_defaults(func=cmd_generate)

    # summary
    p_sum = subs.add_parser("summary", help="Print a JSON summary of a TM7 file")
    p_sum.add_argument("--input", required=True, help="Input TM7 file")
    p_sum.add_argument("--output-file", "-o", help="Output JSON file")
    p_sum.set_defaults(func=cmd_summary)

    # update-threats
    p_upd = subs.add_parser("update-threats", help="Update threat states from Markdown")
    p_upd.add_argument("--tm7", required=True, help="Original TM7 file")
    p_upd.add_argument("--markdown", required=True, help="Reviewed Markdown file")
    p_upd.add_argument("--output", required=True, help="Output TM7 file")
    p_upd.set_defaults(func=cmd_update_threats)

    # validate
    p_val = subs.add_parser("validate", help="Validate a Markdown threat model")
    p_val.add_argument("--input", required=True, help="Input Markdown file")
    p_val.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
