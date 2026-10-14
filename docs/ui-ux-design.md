# GraphSentinel: Design

## 1. Theme
Dark, security-tool feel. Calm background, one accent, color reserved for risk meaning.

## 2. Colors
| Role | Hex |
|---|---|
| Background | `#0B0D12` |
| Surface / cards | `#141822` |
| Border | `#232938` |
| Text primary | `#E6E9F2` |
| Text secondary | `#8B93A7` |
| Accent (primary) | `#7C6CFF` |
| Accent hover | `#9A8DFF` |
| Success / safe | `#2DD4A0` |
| Warning / medium | `#F5B544` |
| Danger / critical | `#FF5C6C` |

**Graph node colors**
| Node | Color |
|---|---|
| Repo | `#E6E9F2` |
| File | `#7C6CFF` |
| Function | `#4DA3FF` |
| Package | `#F5B544` |
| Vuln | `#FF5C6C` |
| Highlighted path | `#2DD4A0` edges, thicker (3px) |

Rules: red only for real vulnerabilities; dim non-path nodes to 25% opacity when a path is highlighted; never rely on color alone (add icons or labels).

## 3. Fonts
- **UI / body:** Inter (fallback: system sans-serif)
- **Code, paths, Cypher:** JetBrains Mono (fallback: monospace)

## 4. Typography scale
| Use | Size | Weight |
|---|---|---|
| Page title | 28px | 700 |
| Section heading | 20px | 600 |
| Body | 15px | 400 |
| Caption / labels | 12px | 500, uppercase, letter-spacing 0.08em |
| Code | 13px | 400 |

Line height 1.5 for body, 1.2 for headings.

## 5. Layout
- Left: chat (about 40%). Right: graph view (about 60%).
- Below graph: tabs "Evidence", "Cypher", "Ingest log".
- Sidebar: repo URL input, ingest button, repo stats.
- Spacing scale 4 / 8 / 16 / 24 px; card radius 10px; 1px borders, no heavy shadows.

## 6. Components
- **Risk badge:** pill with severity color (critical / high / medium / low).
- **Answer card:** answer text, then collapsible "How I got this" showing tool calls.
- **Path chips:** `main.py → utils.py → requests` in mono font.
- **Empty state:** short prompt with three example questions.

## 7. Streamlit theme (`.streamlit/config.toml`)
```toml
[theme]
base = "dark"
primaryColor = "#7C6CFF"
backgroundColor = "#0B0D12"
secondaryBackgroundColor = "#141822"
textColor = "#E6E9F2"
font = "sans serif"
```

## 8. Accessibility
Contrast at least 4.5:1 for text; keyboard-reachable controls; alt text/labels for graph legend.
