# Graph Layout Algorithm Comparison

## Requirements

TM7 threat model diagrams have a few constraints that shape the layout choice:

- Diagrams are usually small, commonly under 100 nodes.
- Data flows are directed and should read left-to-right when possible.
- Trust boundaries are a hard containment constraint for member elements.
- The model has two visual levels: boundaries and elements.
- Microsoft Threat Modeling Tool is sensitive to corrupted or extreme coordinates.
- The skill should remain easy to ship as a VS Code Copilot skill, preferably without external layout binaries.

## Comparison

| Algorithm family | Strengths | Weaknesses for TM7 | Fit |
| --- | --- | --- | --- |
| Existing column/stack heuristic | Simple, deterministic, dependency-free | Ignores graph topology, crossings, self-loops, dense parallel flows, and internal boundary structure | Keep only as legacy reference |
| Force-directed | Good general-purpose aesthetics, flexible constraints, works well for small/medium undirected graphs | Directed flow is weak, deterministic output requires care, hard containment needs extra constraints and overlap removal | Not default |
| Stress majorization | Stronger convergence properties than ad hoc force layouts, good distance preservation | Still not naturally directed or boundary-aware | Possible initializer only |
| Spectral | Fast, deterministic, useful global structure | Does not express DFD flow direction or cluster containment | Possible initializer only |
| Orthogonal | Excellent for box-and-line diagrams, clear edge channels | Full planarization/bend minimization/compaction is complex, TM7 connector model exposes only one handle | Borrow routing ideas |
| Tree | Very readable for rooted trees | Threat models are not trees; cycles and peer services are common | Poor fit |
| Radial/circular | Useful for cyclic or hub-heavy network diagrams | Not natural for data-flow direction or trust-boundary boxes | Poor fit |
| Layered/Sugiyama | Designed for directed graphs, supports left-to-right flow, has mature crossing-reduction heuristics | Needs cycle handling and cluster-aware coordinate assignment | Best default |
| Graphviz `dot` | Mature layered layout, widely used, high quality | Adds external executable or library dependency and DOT translation | Optional backend or oracle |
| Microsoft Automatic Graph Layout | Mature .NET layered layout, Microsoft provenance, supports routing concepts | Adds .NET dependency and integration complexity inside Python skill | Optional future backend |
| ELK | Strong compound graph and layered layout support | Heavy Java/JS integration and packaging friction | Optional future backend |
| Graph neural networks | Active research area, can learn layout or placement heuristics | Needs training data, heavy dependencies, nondeterministic model behavior, no hard coordinate guarantees | Not recommended |

## Recommendation

Use a pure-Python compound layered layout as the default.

The approach should use Sugiyama-style phases adapted for two-level threat-model diagrams:

1. Normalize elements, flows, and trust boundary membership.
2. Build local graphs inside each trust boundary.
3. Build a top-level graph of trust-boundary clusters and ungrouped elements.
4. Break cycles for ranking while preserving original flow direction for rendering.
5. Assign left-to-right layers.
6. Reduce crossings with median or barycenter sweeps.
7. Assign coordinates with explicit spacing and canvas guardrails.
8. Route connectors with side-aware and multi-edge-aware endpoint distribution.

This gives predictable diagrams without shipping Graphviz, MSAGL, ELK, or a neural model. The algorithm is also small enough to test thoroughly in the existing Python suite.

## Why Not GNNs

Graph neural networks are useful for representation learning and some combinatorial optimization tasks, but they are not a practical default for TM7 layout generation today.

A GNN layout solution would need:

- A corpus of good TM7 diagrams for training.
- A loss function that balances crossings, edge length, area, labels, and boundary containment.
- Post-processing to guarantee no overlap and no TMT-invalid coordinates.
- Large runtime dependencies and versioning.
- A deterministic inference story for repeated generation.

For small threat-model diagrams, classical graph drawing heuristics are simpler, more explainable, and easier to validate.

## Future Options

Graphviz `dot`, MSAGL, or ELK can still be useful later as optional quality oracles. A future implementation could expose a `--layout-backend` option with `layered` as the default and external engines as opt-in choices when available locally.
