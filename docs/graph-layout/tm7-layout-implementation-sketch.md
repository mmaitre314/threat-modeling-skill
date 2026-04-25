# TM7 Layout Implementation Sketch

## Goal

Replace the current coordinate heuristic with a deterministic compound layered layout that keeps trust-boundary members inside boundary boxes and makes directed data flows readable.

The implementation should stay in `.github/skills/threat-modeling/tm7_cli.py` and avoid mandatory external layout dependencies.

## Proposed Data Structures

Add small layout-only structures near `TM7Generator`:

- `LayoutOptions`: spacing, padding, canvas guardrails, and rank direction.
- `LayoutBox`: `left`, `top`, `width`, `height` helpers for element and boundary rectangles.
- `LayoutResult`: element positions, boundary positions, and node rank metadata.
- `LayoutEdge`: source GUID, target GUID, flow GUID, and original flow order.

These structures should not affect the threat-model data model. They are an internal coordinate computation layer.

## Layout Pipeline

### 1. Normalize

Resolve each flow endpoint to an element GUID. Build:

- `name_to_guid`
- `guid_to_element`
- `element_to_boundary`
- `boundary_to_elements`

If an element appears in multiple boundaries, choose the first boundary in model order for layout and ignore later duplicate memberships for geometry. Validation can flag this later if needed.

### 2. Build Local Boundary Layouts

For each populated trust boundary:

1. Collect member elements.
2. Collect internal flows whose source and target are both in the boundary.
3. If internal flows exist, run local left-to-right layering.
4. If not, use a compact deterministic grid sorted by degree, generic type, and original order.
5. Compute the boundary rectangle from member rectangles plus padding and label clearance.

### 3. Build Top-Level Graph

Create one top-level node for each populated boundary and one standalone node for each ungrouped element.

For each flow:

- If source and target are in the same boundary, it stays local for connector routing.
- If source and target are in different top-level nodes, create or increment a weighted top-level edge.
- If source and target are the same element, keep it as a self-loop for connector routing, but exclude it from ranking.

### 4. Layer Assignment

Run a deterministic Sugiyama-style ranking:

1. Break cycles for ranking using a greedy feedback-arc heuristic with stable tie-breakers.
2. Assign ranks using longest path from sources.
3. Cap very wide ranks by shifting low-weight or low-degree nodes to adjacent ranks if needed.
4. Preserve model order, name, and GUID as tie-breakers.

### 5. Crossing Reduction

Apply a small fixed number of sweeps because diagrams are under 100 nodes:

1. Left-to-right barycenter or median ordering.
2. Right-to-left barycenter or median ordering.
3. Adjacent swaps when they reduce crossings.

Use edge weights so repeated flows keep strongly connected clusters near each other.

### 6. Coordinate Assignment

Assign left-to-right coordinates by rank:

- `START_X` and `START_Y` define the origin.
- `RANK_GAP` separates layers.
- `NODE_GAP_Y` separates nodes inside a rank.
- Boundary and element dimensions are derived from their contents.

Translate member element coordinates into their boundary box after top-level placement.

Keep coordinates inside the configured guardrail. If a diagram cannot fit, prefer a deterministic wrap by rank band over silently producing coordinates that TMT will auto-correct.

## Connector Routing

Route connectors from the final element rectangles:

- Forward cross-rank flow: East to West.
- Reverse flow: West to East with a larger handle offset.
- Same-rank flow: South to North or North to South, depending on vertical order.
- Same-column flow: South/North, preserving the current behavior.
- Parallel same-direction flows: distribute source and target points along the selected side.
- Bidirectional pairs: bow handles in opposite directions.
- Self-loops: use non-zero coordinates around the source rectangle with a handle outside the rectangle.

The router should not fall back to `(0, 100)` to `(250, 100)` for missing endpoints if that would hide a modeling error. Prefer nil endpoint warnings for threats and deterministic safe connector geometry for flows that can be resolved.

## XML Integration

`TM7Generator._borders_xml` should become:

1. Compute `LayoutResult`.
2. Emit element stencil XML from `LayoutResult.element_positions`.
3. Emit populated trust boundaries as `BorderBoundary` rectangles from `LayoutResult.boundary_positions`.
4. Return positions for `_lines_xml`.

`TM7Generator._lines_xml` should consume the same position map and route connectors using final element rectangles.

The template splicing behavior must stay intact because ElementTree serialization can corrupt namespace-prefixed `i:type` values.

## Tests

Add tests in `.github/skills/threat-modeling/tests/test_tm7_cli.py` for:

- Containment: every boundary member rectangle is inside the generated boundary rectangle.
- No overlap: generated stencils do not overlap in typical clustered diagrams.
- Left-to-right chains: `A -> B -> C` gets increasing `Left` values.
- Cross-boundary ranking: a boundary with outgoing flow appears left of the target boundary.
- Self-loop routing: self-loop connectors have non-zero length and non-default ports/handles.
- Parallel flow routing: multiple connectors for the same source and target do not share identical endpoints.
- Same-column flows still use North/South ports.
- Wide layouts stay inside the validator guardrail.
- Multi-diagram generation keeps unique `z:Id` values.

## Migration Notes

Keep the old heuristic available only as an internal reference during development. Once the layered layout is passing tests, make it the default for `generate_text`.

Do not change STRIDE threat generation, markdown table semantics, threat state mapping, or template namespace splicing as part of this layout work.

If manual layout preservation becomes a requirement, add a separate `preserve` or `relayout` option later. That is outside the first implementation.
