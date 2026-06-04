# SOC Dashboard UI — Frontend Design Sprint Plan

**Stack:** Streamlit + Plotly + custom HTML/CSS injected via `st.markdown(unsafe_allow_html=True)`  
**Branch:** `betul` → PRs into `main`  
**Cadence:** 1-week sprints, 5 tickets per sprint  

---

## Diagnosis — Current Design Debt

| Area | Issue |
|---|---|
| Design tokens | No spacing/radius/shadow system — magic numbers scattered in inline CSS |
| Typography | Only one font size class (`.soc-header`/`.soc-sub`), no scale |
| KPI cards | Default Streamlit `st.metric` — unbranded, no icon, no color-coding by severity |
| Section headers | Inconsistent (`####` markdown vs inline HTML) |
| Chart theming | Mixed `width="stretch"` vs `use_container_width=True`; no chart shell/card |
| Empty states | Plain `st.info("Waiting…")` — no illustration, no call-to-action |
| Sidebar | Functional but flat — no visual grouping, no hierarchy |
| Tab bar | Minimal CSS override; no icon color states, no indicator animation |
| Attack feed | Custom cards exist but border/spacing is uneven |
| Color system | 3 severity colors defined but not applied consistently across all widgets |
| Placeholder tabs | XAI and Admin show `st.info("Coming in Sprint X")` — looks unfinished |

---

## Sprint 1 — Design System Foundation & Layout Skeleton *(Week 1)*

**Goal:** Establish a single source-of-truth CSS layer. Every subsequent sprint builds on top of it. Zero visual regressions.

### S1-01 · Design Token CSS Block
**Priority:** P0 · **Effort:** M

Replace the current ad-hoc `<style>` block with a structured token system.

```css
--color-bg-base:       #0a0e17;
--color-bg-surface:    #0d1220;
--color-bg-card:       rgba(255,255,255,0.04);
--color-border:        rgba(255,255,255,0.08);
--color-border-accent: rgba(88,166,255,0.25);
--color-text-primary:  #c9d1d9;
--color-text-muted:    #9ca5b0;
--color-text-link:     #58a6ff;

--color-safe:          #00CC66;
--color-low:           #3498db;
--color-medium:        #FFD700;
--color-high:          #FFA500;
--color-critical:      #FF4B4B;

--radius-sm:  6px;
--radius-md:  12px;
--radius-lg:  16px;
--shadow-card:  0 2px 8px rgba(0,0,0,0.4);
--shadow-hover: 0 8px 32px rgba(88,166,255,0.12);

--space-1: 4px;  --space-2: 8px;  --space-3: 12px;
--space-4: 16px; --space-5: 20px; --space-6: 24px;

--font-xs:   0.72rem;
--font-sm:   0.82rem;
--font-base: 0.92rem;
--font-lg:   1.05rem;
--font-xl:   1.4rem;
--font-2xl:  1.8rem;
```

All existing inline styles reference these variables. Current hardcoded hex values are removed.

---

### S1-02 · Section Header Component
**Priority:** P0 · **Effort:** S

Create a `section_header(title, subtitle=None, icon=None)` Python helper that renders a consistent header across every panel. Replaces all `st.markdown("#### …")` calls.

```html
<div class="section-header">
  <span class="section-icon">🖥️</span>
  <div>
    <div class="section-title">Live Monitor</div>
    <div class="section-sub">Real-time NIDS detection stream</div>
  </div>
</div>
```

CSS: `border-left: 3px solid var(--color-text-link)`, left-padding, consistent bottom margin.

---

### S1-03 · Chart Shell Card
**Priority:** P0 · **Effort:** S

Wrap every `st.plotly_chart` call in a surface card div:

```html
<div class="chart-card">
  <div class="chart-card__header">
    <span class="chart-card__title">Detection Time Series</span>
    <span class="chart-card__badge">Live</span>
  </div>
  <!-- chart renders here -->
</div>
```

CSS: `background: var(--color-bg-card)`, `border: 1px solid var(--color-border)`, `border-radius: var(--radius-md)`, `padding: var(--space-4)`. Uniform 2px bottom margin between cards.

---

### S1-04 · Global Layout Tightening
**Priority:** P1 · **Effort:** M

- Remove every `st.markdown("---")` divider and replace with CSS margin on the section-header component (dividers are visual noise).
- Standardize all `st.plotly_chart` calls to use `use_container_width=True` (remove `width="stretch"` which is deprecated behavior in newer Streamlit).
- Set consistent chart heights: gauge `220`, pie `300`, time series `300`, histogram `260`, heatmap `300`.
- Set `margin=dict(l=10, r=10, t=36, b=0)` globally on all Plotly layouts via a `_apply_chart_defaults(fig)` helper.

---

### S1-05 · Typography Scale
**Priority:** P1 · **Effort:** S

Define CSS classes `.text-xs`, `.text-sm`, `.text-base`, `.text-lg`, `.text-xl`, `.text-muted`, `.text-accent`, `.text-danger` that use the token variables. Refactor caption/label strings to use these classes instead of inline `font-size` / `color` style attributes.

---

## Sprint 2 — KPI Cards & Header Redesign *(Week 2)*

**Goal:** The top of every tab must communicate status at a glance within 2 seconds.

### S2-01 · Custom KPI Card Component
**Priority:** P0 · **Effort:** L

Replace all `st.metric(…)` calls with a custom `kpi_card(label, value, delta=None, color=None, icon=None, trend=None)` renderer.

Design spec:
```
┌─────────────────────────────┐
│ [icon]  LABEL               │
│                             │
│   1,234          ▲ 12.4%   │
│   value          delta      │
│                             │
│ ───────────────────── trend │
└─────────────────────────────┘
```

- Left border accent color matches severity (`--color-safe`, `--color-critical`, etc.)
- Delta arrow color: green for benign growth, red for attack growth
- Hover: lift + glow using `--shadow-hover`
- The 5 KPIs (Total Flows, Benign, Volumetric, Semantic, Avg Confidence) each get a specific accent color

---

### S2-02 · Page Header Redesign
**Priority:** P0 · **Effort:** M

Replace the plain text header with a two-zone layout:

```
┌─────────────────────────────────────────────────────┐
│  [shield icon]  AI Network IPS                       │
│  SOC — 3-Class LSTM/BiLSTM NIDS                     │
│                                      [live pulse] ●  │
│                              15:42:07 UTC  •  LIVE   │
└─────────────────────────────────────────────────────┘
```

- Left: branding + subtitle
- Right: live clock (updated via Streamlit's autorefresh), live pulse dot animation
- `background: linear-gradient(90deg, rgba(88,166,255,0.05) 0%, transparent 100%)`
- Bottom `border-bottom: 1px solid var(--color-border-accent)`

---

### S2-03 · System Status Bar Redesign
**Priority:** P1 · **Effort:** M

Replace the current 5-column badge row with a horizontal status bar:

```
┌── System Status ────────────────────────────────────┐
│  ● LSTM/BiLSTM  ● Scaler  ● TensorFlow             │
│  ⏳ Scapy  ● Bridge  │  CSV: 12,458 rows  │ 2s ago  │
└─────────────────────────────────────────────────────┘
```

- Colored dot (not emoji) for each service: `background: var(--color-safe)` green circle 8px
- Inline status bar with `flex` layout, `gap: var(--space-4)`
- Data stats on the right side, muted color
- Entire bar sits inside a `chart-card` shell

---

### S2-04 · Risk Gauge Enhancement
**Priority:** P1 · **Effort:** M

- Add an outer ring around the gauge matching the current risk color with CSS `box-shadow: 0 0 0 2px <color>40`
- Add a text label below the gauge with last-updated timestamp
- Critical state: the card border pulses using `criticalPulse` animation (currently applied but only on the inner div — extend to the card shell)
- Non-critical states: static card with subtle colored top-border `border-top: 2px solid <risk-color>`

---

### S2-05 · Tab Bar Polish
**Priority:** P1 · **Effort:** S

- Active tab: filled pill background `background: rgba(88,166,255,0.12)`, colored icon, no bottom border
- Inactive tab: icon desaturated to `opacity: 0.5`
- Hover: background `rgba(255,255,255,0.05)` transition 150ms
- Add `border-radius: var(--radius-sm)` to tab buttons
- Remove the default Streamlit tab underline overriding with `border-bottom: none !important`

---

## Sprint 3 — Charts, Empty States & Data Tables *(Week 3)*

**Goal:** Every data-absent state should look intentional. Every chart should feel like a premium security product.

### S3-01 · Unified Empty State Component
**Priority:** P0 · **Effort:** M

Create `render_empty_state(title, description, icon="📡")` helper used by all charts and feeds when data is absent.

```html
<div class="empty-state">
  <div class="empty-state__icon">📡</div>
  <div class="empty-state__title">Waiting for traffic data</div>
  <div class="empty-state__desc">
    The live bridge is active. Flows will appear here automatically.
  </div>
</div>
```

CSS: centered flex column, muted colors, subtle dashed border, `min-height: 180px`. Replace all `st.info("Waiting for data…")` calls.

---

### S3-02 · Chart Color & Grid Consistency
**Priority:** P0 · **Effort:** M

Apply to every Plotly figure via `_apply_chart_defaults(fig)`:

```python
fig.update_layout(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(255,255,255,0.03)",
    font=dict(family="Inter", color="#c9d1d9", size=11),
    xaxis=dict(gridcolor="rgba(255,255,255,0.06)", zerolinecolor="rgba(255,255,255,0.1)"),
    yaxis=dict(gridcolor="rgba(255,255,255,0.06)", zerolinecolor="rgba(255,255,255,0.1)"),
    hoverlabel=dict(bgcolor="#1a2235", bordercolor="rgba(255,255,255,0.15)", font_color="#c9d1d9"),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,0,0,0)"),
)
```

---

### S3-03 · Attack Feed Card Redesign
**Priority:** P1 · **Effort:** M

Current cards exist but need polish. New spec:

```
┌─────────────────────────────────────────────┐
│  ████  192.168.1.105          [BLOCKED]      │
│        2026-06-04 15:42:07                   │
│  ──────────────────────────────────────────  │
│  Volumetric DDoS detected. 1,240 flows/s    │
│  blocked by firewall rule #42.              │
└─────────────────────────────────────────────┘
```

- Left: 4px colored accent bar (red=BLOCKED, yellow=ALLOWED, green=NORMAL)
- IP in `font-weight: 700`, timestamp in `--font-xs text-muted`
- Action badge: pill shape, color-coded, all-caps
- Thin divider between header and detail text
- New card: gentle entry animation `@keyframes slideIn` (translateY -8px → 0, opacity 0 → 1, 200ms)

---

### S3-04 · Recent Detections Table Styling
**Priority:** P1 · **Effort:** M

Replace raw `st.dataframe` with styled AgGrid (already imported). Apply per-row color coding:

- Benign rows: no highlight
- Volumetric rows: `background: rgba(255,75,75,0.06)`
- Semantic rows: `background: rgba(255,165,0,0.08)`
- Action column: colored badge pills via `cellStyle` JavaScript
- Timestamp column: formatted as relative time ("2 min ago") with tooltip showing full timestamp

---

### S3-05 · Placeholder Tab Redesign (XAI & Admin)
**Priority:** P2 · **Effort:** S

Replace the raw `st.info("🚧 Coming in Sprint X…")` with intentional "coming soon" feature-preview cards:

```
┌─────────────────────────────────────┐  ┌──────────────────────────────┐
│  🔮  SHAP Waterfall Chart           │  │  🔮  Feature Importance Bar  │
│  Prediction explanation per flow    │  │  Top-N contributing features │
│  [● Planned for Sprint 3]           │  │  [● Planned for Sprint 3]    │
└─────────────────────────────────────┘  └──────────────────────────────┘
```

CSS: dashed border `border: 1px dashed var(--color-border)`, muted background, `opacity: 0.65`. Grid of 2×2 preview cards.

---

## Sprint 4 — Sidebar & Navigation *(Week 4)*

**Goal:** The sidebar is the SOC operator's control room. It should feel structured and fast.

### S4-01 · Sidebar Visual Sections
**Priority:** P0 · **Effort:** M

Add `sidebar_section(title)` helper that renders a labeled divider with uppercase letter-spacing:

```html
<div class="sidebar-section-label">DATA SOURCE</div>
```

Groups: `DATA SOURCE` (time window), `LIVE MODE`, `AI ENGINE` (model selector), `FIREWALL` (IP unblock). Currently separated by `st.sidebar.markdown("---")` which is visually weak.

---

### S4-02 · Threat Level Banner Enhancement
**Priority:** P0 · **Effort:** M

New spec:

```
┌─────────────────────────────┐
│   THREAT LEVEL — LAST 60s   │
│                             │
│       🔴  CRITICAL          │
│                             │
│   ████████████░░░░  80%     │
│   Risk score progress bar   │
└─────────────────────────────┘
```

- Add a mini progress bar showing risk score `1–5` as percentage
- Critical: pulsing border animation extended to the banner
- Include a small "last checked: 15:42:07" sub-label

---

### S4-03 · Model Status Card
**Priority:** P1 · **Effort:** S

Merge the selectbox and current model display div into a single card:

```
┌─── AI ENGINE ───────────────┐
│  BiLSTM          ● Active   │
│  bilstm_best.keras          │
│  ─────────────────────────  │
│  [  Select Model  ▾  ]      │
└─────────────────────────────┘
```

Card sits inside a `chart-card` shell. Active indicator dot pulses green when `data_flowing=True`.

---

### S4-04 · Sidebar Live Stats Mini-Panel
**Priority:** P2 · **Effort:** M

Compact real-time summary drawn from the already-loaded `df_live_full`:

```
┌─── LAST 60s ────────────────┐
│  Flows     Attacks   Blocks  │
│  1,284       43        12    │
└─────────────────────────────┘
```

Three inline stat numbers, `--font-xl` weight, muted labels. Updates on every autorefresh cycle.

---

### S4-05 · IP Unblock UX Improvements
**Priority:** P2 · **Effort:** S

- Add IP format validation feedback inline (green checkmark / red X as user types)
- Add a second "Block IP" button alongside "Unblock IP"
- Show a small list of recently actioned IPs in the session below the input (drawn from `st.session_state`)

---

## Sprint 5 — Polish, Animation & Accessibility *(Week 5)*

**Goal:** Elevate from "functional dark theme" to "premium SOC product."

### S5-01 · Micro-animation System
**Priority:** P1 · **Effort:** M

Define reusable keyframe animations in the CSS token block:

```css
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: none; }
}
@keyframes pulseGlow {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255,75,75,0.4); }
  50%       { box-shadow: 0 0 0 8px rgba(255,75,75,0); }
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-8px); }
  to   { opacity: 1; transform: none; }
}
@keyframes shimmer {
  0%   { background-position: -200% 0; }
  100% { background-position:  200% 0; }
}
```

Apply: `fadeIn` on chart cards on mount (staggered 200ms delay per card), `slideIn` on attack feed entries, `pulseGlow` on critical risk elements.

---

### S5-02 · Loading Skeleton Screens
**Priority:** P1 · **Effort:** M

When `live_df.empty` show a skeleton card instead of empty state or spinner:

```html
<div class="skeleton-card">
  <div class="skeleton-line" style="width:40%"></div>
  <div class="skeleton-line" style="width:70%; height:2rem; margin:12px 0"></div>
  <div class="skeleton-line" style="width:55%"></div>
</div>
```

```css
.skeleton-line {
  background: linear-gradient(
    90deg,
    rgba(255,255,255,0.04) 0%,
    rgba(255,255,255,0.08) 50%,
    rgba(255,255,255,0.04) 100%
  );
  background-size: 200% 100%;
  animation: shimmer 1.6s infinite;
  border-radius: var(--radius-sm);
  height: 14px;
}
```

Applied to: KPI row, time series chart area, attack feed area.

---

### S5-03 · Color Contrast & Accessibility Audit
**Priority:** P0 · **Effort:** M

Audit every text/background pair against WCAG AA (4.5:1 for normal text, 3:1 for large):

- `--color-text-muted` on `--color-bg-card`: lightened to `#9ca5b0` (~4.6:1 ✓)
- Badge text colors: verify `badge-ok`, `badge-warn`, `badge-err` all pass
- Chart axis labels: ensure underlying card is dark enough
- Tab bar active `#58a6ff` on `#0a0e17`: 5.1:1 ✓
- Add `aria-label` attributes to all custom HTML interactive elements (attack feed items, firewall viewer buttons)

---

### S5-04 · Responsive Column Guards
**Priority:** P2 · **Effort:** S

Add CSS `@media` overrides for narrow browser windows:

```css
@media (max-width: 1100px) {
  [data-testid="column"] { min-width: 180px !important; }
}
```

Specifically guard the 5-column metric row and the 3-column system status bar — these break badly at narrow widths.

---

### S5-05 · Final Visual QA Checklist
**Priority:** P0 · **Effort:** S

Run before closing the sprint:

- [ ] All `st.markdown("---")` removed; spacing from CSS only
- [ ] No hardcoded hex colors outside the token block
- [ ] All charts use `use_container_width=True`; no `width="stretch"`
- [ ] `_apply_chart_defaults(fig)` called on every Plotly figure
- [ ] All empty/waiting states use `render_empty_state()`
- [ ] Attack feed cards use the `slideIn` animation
- [ ] Skeleton screens visible when CSV is absent
- [ ] No console errors in browser dev tools

---

## Backlog (Post-Sprint 5)

| Item | Why deferred |
|---|---|
| Dark/light mode toggle | Requires full CSS variable inversion layer — significant scope |
| Customizable dashboard layout (drag cards) | Streamlit doesn't natively support it; requires a JS component |
| Per-tab notification badges | Requires Streamlit component or JS injection |
| Chart export buttons (PNG/SVG) | Plotly modebar — just needs enabling and styling |
| Real-time WebSocket feed | Architecture change, not UI work |

---

## Effort Summary

| Sprint | Focus | Story Points |
|---|---|---|
| Sprint 1 | Design system foundation | 13 |
| Sprint 2 | KPI cards + header | 15 |
| Sprint 3 | Charts + tables + empties | 14 |
| Sprint 4 | Sidebar + navigation | 12 |
| Sprint 5 | Animation + a11y + QA | 11 |
| **Total** | | **65** |

Each sprint is self-contained and ships a visible, testable improvement. Sprint 1 is a hard prerequisite — Sprints 2–5 depend on the token system being in place.
