# TM7 Layout Investigation

## Summary

A user reported that generated TM7 threat model files opened in Microsoft Threat Modeling Tool with corrupted coordinates and unreadable diagrams. The attached screenshots show long overlapping connector bands, boundary lines cutting through unrelated objects, and a TMT warning that line or border coordinates were automatically corrected.

The current skill generates valid TM7 XML, but its layout algorithm is a simple placement heuristic. It groups elements by trust boundary, stacks members vertically inside each boundary, and places groups left-to-right until a fixed width limit is reached. This ignores the directed data-flow graph, so moderately connected diagrams can become visually tangled even when the file deserializes.

The recommended fix is a deterministic, pure-Python, two-level compound layered layout. Trust boundaries become top-level clusters, elements are laid out inside their clusters, cross-boundary flows are collapsed into weighted top-level edges, and connectors are routed with stable ports and explicit self-loop/parallel-flow handling.

## Current Algorithm

The template-safe generation path is in `.github/skills/threat-modeling/tm7_cli.py`:

- `TM7Generator._generate_from_template` splices generated `Borders` and `Lines` XML into a TM7 template to avoid DataContractSerializer namespace corruption.
- `TM7Generator._borders_xml` computes element and populated trust-boundary rectangles.
- `TM7Generator._lines_xml` computes connector endpoints, handles, and ports.

`_borders_xml` currently does the following:

1. Builds a map from element name to trust boundary name.
2. Creates ordered groups: ungrouped elements first, then populated boundaries.
3. Places ungrouped elements horizontally.
4. Places each populated boundary as a vertical stack of member elements inside a `BorderBoundary` rectangle.
5. Wraps to a new row when `x_cursor + group_width > 1200`.

`_lines_xml` currently does the following:

1. Resolves flow endpoints from names or GUIDs.
2. Uses East/West ports for left-to-right or right-to-left flows.
3. Uses North/South ports for same-column flows.
4. Offsets parallel flows on the same directed pair by 15 px.
5. Offsets connector handles by 50 px for bidirectional pairs.
6. Emits empty trust boundaries as `LineBoundary` entries at fixed x coordinates.

There is also an older ElementTree path in `TM7Generator.generate`, `_add_elements_to_borders`, and `_add_flows_to_lines`. That path uses even simpler horizontal placement and incomplete connector geometry. Future layout changes should centralize coordinate generation so both paths do not diverge.

## Failure Modes

The current algorithm is deterministic and small, but it is not graph-aware. Important failure modes are:

- Crossings are not minimized because node order is unrelated to data-flow topology.
- Dense multi-edge and bidirectional flows still overlap once there are more than two connectors between the same logical pair.
- Self-loops have no special geometry and can collapse into zero-length or nearly invisible connectors.
- Elements inside the same boundary are always stacked vertically, even when their internal flows imply a left-to-right chain.
- Empty or under-specified trust boundaries are emitted as fixed-position vertical `LineBoundary` elements, which can cut across the whole diagram.
- Large models can remain within the x guardrail only by growing downward, producing tall diagrams with long connector bands.
- Parsed `Element.x` and `Element.y` values from existing TM7 files are not reused during generation, so round-trips discard manual layout.

The local validator in `tools/tm7_validate.cs` already checks several geometry risks: all-zero line coordinates, zero-length connectors, duplicate connector endpoints, unresolved endpoint GUIDs, borders beyond a 1500 px guardrail, and connectors that reference elements outside the same drawing surface.

## Literature Review

Graph drawing quality measures relevant to TM7 are edge crossings, drawing area, aspect ratio, edge simplicity, edge length consistency, angular resolution, label overlap avoidance, and containment preservation.

Force-directed layouts such as Eades, Kamada-Kawai, Fruchterman-Reingold, and stress majorization are flexible and often attractive for small to medium graphs. They are less ideal here because TM7 threat models are directed data-flow diagrams with hard boundary containment. Force layouts also need careful seeding and overlap removal to remain deterministic.

Spectral layouts are fast and stable for showing global graph structure, but they do not naturally express directed left-to-right flow or hard cluster containment. They are useful as an initializer, not as the primary algorithm.

Orthogonal layouts fit box-and-line diagrams well and are common in VLSI and flowchart-like drawing. Full orthogonal drawing requires planarization, bend minimization, and compaction. TM7 connectors expose one handle rather than arbitrary polyline bends, so a full orthogonal router is more complex than the current skill needs.

Tree, radial, and circular layouts are specialized. They do not match general data-flow diagrams with cycles, peer services, and cross-boundary flows.

Layered, or Sugiyama-style, layouts are designed for directed graphs. They use cycle handling, layer assignment, crossing minimization, and coordinate assignment. Graphviz `dot`, Microsoft Automatic Graph Layout, and ELK all implement mature variants. This family best matches a threat-model diagram because most data flows should read left-to-right.

Graph neural networks and learned graph placement are interesting research areas, but they need training data, objective functions, model packaging, and post-processing to guarantee hard constraints. They are not a good default solution for small deterministic TM7 generation.

## Selected Algorithm

Use a deterministic two-level compound layered layout:

1. Treat each populated trust boundary as a cluster.
2. Treat ungrouped elements as standalone top-level nodes.
3. Lay out elements inside each boundary with a local layered layout when internal flows exist, otherwise with a compact grid ordered by type and degree.
4. Collapse cross-boundary flows into weighted top-level edges.
5. Run a left-to-right layered layout over clusters and standalone nodes.
6. Expand cluster coordinates back into element rectangles.
7. Route connectors from stable ports with explicit handling for forward, reverse, same-layer, same-column, parallel, and self-loop flows.

This keeps the implementation shippable in pure Python, avoids external binaries, and matches the expected size of threat-model diagrams, typically under 100 nodes.

## Implementation Sketch

Add layout helper structures to `tm7_cli.py` near the TM7 generator:

- `LayoutOptions` for spacing, padding, and canvas guardrails.
- `LayoutBox` for element and boundary rectangles.
- `LayoutResult` for element positions, boundary positions, and rank metadata.

Replace the body of `_borders_xml` with a call to a layout computation helper. Keep XML serialization separate from coordinate assignment so tests can validate geometry directly.

Update `_lines_xml` to route connectors based on the computed positions. The router should distribute endpoints along the selected side, keep parallel flows distinct, draw self-loops with non-zero coordinates, and avoid all-zero fallback coordinates for unresolved endpoints.

Centralize layout use so the template-safe path and fallback path do not produce conflicting geometry.

## Verification Plan

Automated checks:

1. Run `python -m unittest discover -s tests -v` from `.github/skills/threat-modeling`.
2. Generate TM7 from `samples/simple.md`, `samples/complex.md`, `samples/azure-vm.md`, and `_tmp/items.md`.
3. Validate generated files with `tools\bin\Release\net48\tm7_validate.exe` or `dotnet run --project tools -c Release -- <files>` on a Windows machine with TMT installed.

Geometry checks:

- Every boundary member rectangle is inside its `BorderBoundary` rectangle.
- Stencil rectangles do not overlap.
- Coordinates remain inside the configured guardrail.
- Connector coordinates are never all zero.
- Self-loop connectors are non-zero length.
- Parallel connectors do not share identical endpoints.
- Cross-boundary acyclic chains progress left-to-right.

Manual check:

Open generated small, complex, and reported-problem models in Microsoft Threat Modeling Tool. Confirm no auto-correction dialog appears and the diagram is readable without manual rearrangement.
