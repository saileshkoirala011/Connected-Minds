# GraphSentinel: UI/UX Design

Dark, calm, security-tool look. One accent color; red is reserved for real vulnerabilities.

## 1. Color palette
| Role | Hex |
|---|---|
| Background | `#0B0D12` |
| Surface / cards | `#141822` |
| Border | `#232938` |
| Text primary | `#E6E9F2` |
| Text secondary | `#8B93A7` |
| Accent | `#7C6CFF` (hover `#9A8DFF`) |
| Safe | `#2DD4A0` |
| Warning | `#F5B544` |
| Critical | `#FF5C6C` |

Graph nodes: Repo `#E6E9F2`, File `#7C6CFF`, Function `#4DA3FF`, Package `#F5B544`, Vuln `#FF5C6C`. Answer path edges `#2DD4A0`, 3px; everything else dims to 25% opacity when a path is active. Never rely on color alone: add labels or icons.

## 2. Typography
| Use | Font | Size | Weight |
|---|---|---|---|
| Body / UI | Inter (fallback sans-serif) | 15px | 400 |
| Page title | Inter | 28px | 700 |
| Section heading | Inter | 20px | 600 |
| Labels | Inter, uppercase, 0.08em spacing | 12px | 500 |
| Code, paths, Cypher | JetBrains Mono (fallback monospace) | 13px | 400 |

Line height 1.5 body, 1.2 headings.

## 3. Layout
```
┌───────────────┬──────────────────────────────┬─────────────────────────────┐
│ SIDEBAR       │ CHAT (40%)                   │ GRAPH (60%)                 │
│ GraphSentinel │ [example question chips]     │  interactive graph          │
│ Repo URL      │ user message                 │  legend: ● File ● Function  │
│ [Ingest repo] │ answer card                  │         ● Package ● Vuln    │
│ Repo selector │   badge: LIKELY REACHABLE    ├─────────────────────────────┤
│ Stats         │   path chips                 │ [Evidence] [Cypher] [Log]   │
│               │ [ask a question…]  [Send]    │ tab content                 │
└───────────────┴──────────────────────────────┴─────────────────────────────┘
```
Spacing scale 4/8/16/24 px; card radius 10px; 1px borders; no heavy shadows. On narrow screens, stack: chat above, graph below.

## 4. Components
| Component | Style |
|---|---|
| Primary button | Accent fill, white text, 8px radius; disabled at 40% opacity |
| Text input | Surface fill, border, accent border on focus |
| Example chip | Pill, border only, accent on hover |
| Answer card | Surface fill; answer text; collapsible "How I got this" |
| Risk badge | Pill: Critical red, High orange, Medium amber, Low blue; plus text label |
| Confidence badge | "LIKELY REACHABLE" (warning) or "IMPORT ONLY" (secondary) |
| Path chips | Mono font: `main.py → utils.py → requests → CVE-XXXX` |
| Progress steps | Vertical list with check, spinner, or pending dot |
| Error banner | Critical-tinted surface, plain sentence, retry button |
| Empty state | Centered title, one sentence, three example chips |
| Stats | Small cards: Files, Functions, Packages, CVEs |

## 5. Screens (rough look)
- **Empty:** sidebar with URL field; main area shows "Paste a public Python repo to begin" and example chips (disabled until ingest).
- **Ingesting:** progress steps replace the chat area; graph panel shows a skeleton.
- **Ready:** overview graph (top critical files and packages), summary card at top of chat.
- **Answer:** highlighted path in graph; answer card with badges; Evidence tab populated.
- **Error:** banner above chat; previous state kept.

## 6. Interaction details
Graph: zoom, drag, hover tooltip with node type and path; click shows properties box. Limit the view to about 150 nodes; show "+N more" and let the user expand. Animate path highlight briefly (under 400 ms).

## 7. Accessibility
Text contrast at least 4.5:1; keyboard-reachable controls; legend and badges carry text labels; no motion that cannot be disabled.

## 8. Streamlit theme (`.streamlit/config.toml`)
```toml
[theme]
base = "dark"
primaryColor = "#7C6CFF"
backgroundColor = "#0B0D12"
secondaryBackgroundColor = "#141822"
textColor = "#E6E9F2"
font = "sans serif"
```
