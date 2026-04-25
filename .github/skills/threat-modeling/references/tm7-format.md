# TM7 XML Format Reference

TM7 is the XML file format used by the [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool). This document describes the XML structure for developers working with the CLI.

## Namespaces

| Prefix | URI | Purpose |
|--------|-----|---------|
| (default) | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model` | Top-level model elements |
| `a:` | `http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase` | Knowledge base, threat types, element types |
| `b:` | `http://schemas.microsoft.com/2003/10/Serialization/Arrays` | Serialization arrays (KeyValuePairs, lists) |
| `d:` | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts` | Abstract element types (Guid, Properties, etc.) |

## Top-Level Structure

All of the following child elements are **required** — TMT will fail to deserialize
the file if any are missing.

```xml
<ThreatModel>
  <DrawingSurfaceList>         <!-- Visual diagrams (DFD pages) -->
    <DrawingSurfaceModel>
      <Borders>                <!-- Elements: Processes, Data Stores, External Interactors, Trust Boundaries -->
      <Lines>                  <!-- Data Flows and line-type Trust Boundaries -->
      <Header>                 <!-- Diagram tab label -->
      <Zoom>                   <!-- Zoom level (1 = 100%) -->
    </DrawingSurfaceModel>
  </DrawingSurfaceList>
  <MetaInformation>            <!-- Model metadata -->
    <ThreatModelName>
    <Owner>
    <Reviewer>
    <HighLevelSystemDescription>
    <Assumptions>
    <ExternalDependencies>
    <Contributors>
  </MetaInformation>
  <Notes>                      <!-- User notes -->
  <ThreatInstances>            <!-- Generated/custom threats -->
  <ThreatGenerationEnabled>    <!-- true/false -->
  <Validations>                <!-- Validation results -->
  <Version>                    <!-- Format version (e.g. 4.3) -->
  <KnowledgeBase>              <!-- Element types, threat generation rules (~1 MB) -->
  <Profile>                    <!-- Template profile -->
    <PromptedKb />
  </Profile>
</ThreatModel>
```

## Element Types (GenericTypeId)

| GenericTypeId | Description | Visual Shape | `i:type` |
|---------------|-------------|--------------|----------|
| `GE.EI` | External Interactor | Rectangle | `StencilRectangle` |
| `GE.P` | Process | Circle/Ellipse | `StencilEllipse` |
| `GE.DS` | Data Store | Parallel lines | `StencilParallelLines` |
| `GE.A` | Annotation | Rectangle (text note) | `StencilRectangle` |
| `GE.DF` | Data Flow | Arrow/connector | `Connector` |
| `GE.TB` | Trust Boundary (rectangular) | Dashed rectangle | — |
| `GE.TB.L` | Trust Boundary (line) | Dashed line | `LineBoundary` |
| `GE.TB.B` | Trust Boundary (box, generic) | Dashed rectangle | `BorderBoundary` |
| `63e7829e-...` | Trust Boundary (box, typed) | Dashed rectangle | `BorderBoundary` |
| `DRAWINGSURFACE` | Drawing Surface | Container (the diagram page itself) | — |

> **BorderBoundary vs LineBoundary:** TMT has two visual forms for trust
> boundaries.  *LineBoundary* is a dashed vertical/diagonal line stored in the
> **Lines** section.  *BorderBoundary* is a dashed rectangle stored in the
> **Borders** section with `GenericTypeId` =
> `63e7829e-c420-4546-9336-0194c0113281` (the well-known GUID for the
> "General Network" boundary family).  The parser must recognise both and
> must **not** treat `BorderBoundary` entries as DFD elements.
>
> **Annotations** (`GE.A`) are freeform text notes placed on the diagram.
> They should be skipped when building the element list.

## Common TypeIds

| TypeId | GenericType | Description |
|--------|------------|-------------|
| `SE.P.TMCore.WebApp` | GE.P | Web Application |
| `SE.P.TMCore.WebServer` | GE.P | Web Server |
| `SE.P.TMCore.WCF` | GE.P | WCF Service |
| `SE.DS.TMCore.SQL` | GE.DS | SQL Database |
| `SE.DS.TMCore.NoSQL` | GE.DS | NoSQL Database |
| `SE.DS.TMCore.FileSystem` | GE.DS | File System |
| `SE.EI.TMCore.Browser` | GE.EI | Web Browser |
| `SE.EI.TMCore.AuthProvider` | GE.EI | Authentication Provider |
| `SE.DF.TMCore.HTTP` | GE.DF | HTTP Data Flow |
| `SE.DF.TMCore.HTTPS` | GE.DF | HTTPS Data Flow |
| `SE.DF.TMCore.ALPC` | GE.DF | Local Procedure Call |
| `SE.DF.TMCore.IPsec` | GE.DF | IPsec Data Flow |
| `SE.TB.L.TMCore.Internet` | GE.TB | Internet Trust Boundary |
| `SE.TB.L.TMCore.Machine` | GE.TB | Machine Trust Boundary |

## Element Properties

Each element has a `Properties` collection of typed attributes:

```xml
<Properties>
  <anyType xsi:type="b:StringDisplayAttribute">
    <DisplayName>Name</DisplayName>
    <Name/>
    <Value xsi:type="c:string">My Element</Value>
  </anyType>
  <anyType xsi:type="b:BooleanDisplayAttribute">
    <DisplayName>Out Of Scope</DisplayName>
    <Name>71f3d9aa-b8ef-4e54-8126-607a1d903103</Name>
    <Value xsi:type="c:boolean">false</Value>
  </anyType>
  <anyType xsi:type="b:ListDisplayAttribute">
    <DisplayName>Authenticates Itself</DisplayName>
    <Name>authenticatesItself</Name>
    <Value xsi:type="a:ArrayOfstring">
      <string>Not Applicable</string>
      <string>No</string>
      <string>Yes</string>
    </Value>
    <SelectedIndex>0</SelectedIndex>
  </anyType>
</Properties>
```

## Threat Instance Structure

```xml
<KeyValueOfstringThreatpc_P0_PhOB>
  <Key>{ThreatTypeId}{SourceGuid}{FlowGuid}{TargetGuid}</Key>
  <Value>
    <ChangedBy>username</ChangedBy>
    <DrawingSurfaceGuid>...</DrawingSurfaceGuid>
    <FlowGuid>...</FlowGuid>
    <Id>25</Id>
    <InteractionKey>sourceGuid:flowGuid:targetGuid</InteractionKey>
    <ModifiedAt>2024-01-01T00:00:00Z</ModifiedAt>
    <Priority>High</Priority>
    <Properties>
      <KeyValueOfstringstring>
        <Key>Title</Key>
        <Value>SQL Injection</Value>
      </KeyValueOfstringstring>
      <KeyValueOfstringstring>
        <Key>UserThreatCategory</Key>
        <Value>Tampering</Value>
      </KeyValueOfstringstring>
      <KeyValueOfstringstring>
        <Key>UserThreatDescription</Key>
        <Value>...</Value>
      </KeyValueOfstringstring>
      <!-- Custom properties use GUIDs as keys -->
    </Properties>
    <SourceGuid>...</SourceGuid>
    <State>NeedsInvestigation</State>
    <TargetGuid>...</TargetGuid>
    <TypeId>T7</TypeId>
  </Value>
</KeyValueOfstringThreatpc_P0_PhOB>
```

## Threat States

| XML Value | Display Name |
|-----------|-------------|
| `NeedsInvestigation` | Needs Investigation |
| `NotApplicable` | Not Applicable |
| `Mitigated` | Mitigated |
| `NotStarted` | Not Started |
| `AutoGenerated` | Auto Generated |

## STRIDE Categories

| Code | Full Name |
|------|-----------|
| S | Spoofing |
| T | Tampering |
| R | Repudiation |
| I | Information Disclosure |
| D | Denial of Service |
| E | Elevation of Privilege |

## Known Property GUIDs

| GUID | Label |
|------|-------|
| `71f3d9aa-b8ef-4e54-8126-607a1d903103` | Out Of Scope |
| `752473b6-52d4-4776-9a24-202153f7d579` | Reason For Out Of Scope |
| `f9e02b87-2914-407e-bd11-97353ef43162` | Risk |
| `941f9317-678b-4a2e-807a-a820331bec42` | Team |
| `44490cdf-6399-4291-9bde-03dca6f03c11` | Mitigation |
| `bc9c6e2a-15d0-4863-9cac-589e51e4ca1e` | Priority |

## Connector Coordinate Rules

Each `Connector` (data flow) in the Lines section carries endpoint and
handle coordinates that control the visual path of the arrow.

The CLI's template-safe TM7 generator computes coordinates with a deterministic
compound layered layout. Elements inside rectangular trust boundaries are laid
out within their parent boundary first; populated boundaries and standalone
elements are then arranged as top-level nodes from left to right using data-flow
edges. This keeps BorderBoundary containment valid while making most flows read
in their natural direction.

### Direction-Aware Endpoints

Connectors are direction-aware.  When the **source element is to the left**
of the target, the arrow departs from the right edge of the source and
arrives at the left edge of the target:

| Field | Value | Ports |
|-------|-------|-------|
| SourceX | source.Left + source.Width (right edge) | PortSource = `East` |
| SourceY | source.Top + source.Height / 2 (vertical centre) | |
| TargetX | target.Left (left edge) | PortTarget = `West` |
| TargetY | target.Top + target.Height / 2 (vertical centre) | |

When the source is to the **right** of the target, the edges and ports
are reversed (`West` → `East`).

When the source and target are stacked vertically with nearly the same X
coordinate, the connector uses South/North ports. Self-loops use a non-zero
loop from the element edge back to its top edge so TMT does not collapse the
line.

### Bidirectional Curve Offsets

When two flows connect the same pair of elements in opposite directions
(A→B and B→A), their arrows must bow in opposite directions so they
don't overlap.  This is achieved by offsetting HandleY:

- **First flow**: `HandleY = midpointY − OFFSET` (curves upward)
- **Second flow**: `HandleY = midpointY + OFFSET` (curves downward)

HandleX is always the horizontal midpoint between source and target.
An offset of ~50 px produces visually distinct curves matching TMT's
default layout.

Multiple flows with the same source and target are also spread along the
source/target element edges. This prevents duplicate connector endpoint
coordinates, which TMT can otherwise normalize into unreadable overlapping
arrows.

### LineBoundary Coordinates

Trust boundary lines (type `LineBoundary`) are vertical lines spanning
the element area.  SourceX ≈ TargetX, SourceY = top of area,
TargetY = bottom of area. Empty trust boundaries are placed to the right of
the current drawing area instead of through existing elements.

## Serialization Gotchas

TMT uses .NET **DataContractSerializer** which produces XML with several
quirks that must be preserved for the file to load successfully.

### `z:Id` / `z:Ref` Reference Attributes

DataContractSerializer emits `z:Id="i1"` attributes (namespace
`http://schemas.microsoft.com/2003/10/Serialization/`) on objects it
serializes.  `DrawingSurfaceModel` and `KnowledgeBase` carry these.
Dropping or renumbering them causes deserialization failures.

**Allocation scheme:** The default template uses `i1` and `i2`.  Generated
elements use `i3` through `i(2 + N)` where N is the element count.  Flows
and trust boundaries continue from `i(3 + N)` onward.  Each entry
(**including each trust boundary**) must increment the counter to avoid
duplicates.

### Namespace-Prefixed `xsi:type` Values

Attribute values like `i:type="b:StringDisplayAttribute"` contain a
**namespace prefix** (`b:`) that is resolved against the `xmlns:b`
declaration **on or above that element**.  Python's `xml.etree.ElementTree`
hoists namespace declarations to the root on write, reassigning prefixes.
This silently corrupts every `xsi:type` value because the prefix now
points to a different namespace.

**Workaround:** The CLI uses raw-text splicing (`_generate_from_template`)
instead of `ElementTree.write()` when a template is available.  Only the
variable sections (MetaInformation children, Borders, Lines,
ThreatInstances) are replaced via regex; all other bytes are preserved
verbatim.

### KnowledgeBase and Profile Are Required

TMT's `KnowledgeBase..ctor` throws a `NullReferenceException` if the
`<KnowledgeBase>` element is absent.  The `<Profile>` element (containing
`<PromptedKb />`) is also required.  Together they account for ~1 MB of
XML in every TM7 file.

### Whitespace Sensitivity

DataContractSerializer treats element text content literally — a
`<ThreatModelName>` with leading/trailing whitespace or newlines will
load that whitespace as part of the model name.  Do not auto-format
TM7 files.  The `references/` directory includes a `.gitattributes`
marking `*.tm7` as binary to prevent this.

### GUID Fields Must Never Be Empty

All GUID-typed fields (`FlowGuid`, `SourceGuid`, `TargetGuid`,
`DrawingSurfaceGuid`, etc.) must contain a valid GUID.  An empty string
causes `FormatException: Unrecognized Guid format` during deserialization.
When a GUID cannot be resolved, use the nil GUID
`00000000-0000-0000-0000-000000000000`.
