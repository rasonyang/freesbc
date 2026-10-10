# Admin UI

How the embedded WebUI (`internal/admin/webui`) is built and the rules for
changing it. `docs/design.md` §13.7 describes what it does; this file says how
to keep it consistent.

## Decisions

| Decision | Reason |
|---|---|
| shadcn/ui **tokens**, not shadcn **components** | The token set is plain CSS variables. The components need React, Tailwind, Radix and a Node build in a Go repo with zero runtime dependencies. We take the look and leave the toolchain. |
| No framework, no build step | The UI is a few views over the admin endpoints. Everything is `//go:embed`ed and served as written; `git diff` shows exactly what ships. |
| Separate files under `assets/`, nothing inline | Lets the UI run under a strict CSP (`script-src 'self'; style-src 'self'`, no `unsafe-inline`). The admin plane exposes the unredacted config file, so it is worth protecting from script injection and framing. |
| `light-dark()` instead of a `.dark` block | Each colour is written once. The OS preference works with no script and no flash; `data-theme` pins a choice. |
| Browser floor: Chrome/Edge 123, Firefox 120, Safari 17.5 | Required by `light-dark()` (2024). Older browsers lose colours; this is an operator console, not a public page. |

## Files and layers

```
webui/
  index.html          markup only: structure, ids, aria, icon sprite
  assets/tokens.css   1. shadcn neutral  2. FreeSBC status  3. scale
  assets/ui.css       components; consumes tokens only
  assets/theme.js     pins light/dark; loaded sync in <head>
  assets/app.js       polling, rendering, config view, candidate validation and diff; loaded defer
```

Dependencies run one way: `tokens.css ← ui.css ← index.html ← app.js`.
A component never defines a base colour; a page never styles itself; script
never writes a colour.

## Tokens

### Section 1: shadcn neutral (shared contract)

Same names and values as the shadcn/ui neutral theme
(<https://ui.shadcn.com/docs/theming>). Any shadcn codebase in the stack
(`web-sip-phone`, for example) can share values with this file 1:1.

- Never rename or remove a token here. To track upstream, copy the new
  values in: the `:root` value is the first `light-dark()` argument, the
  `.dark` value the second.
- Use tokens as **pairs**: text on a surface uses that surface's
  `-foreground`.

| Surface | Text on it | Use |
|---|---|---|
| `--background` | `--foreground`, `--muted-foreground` | page |
| `--card` | `--card-foreground`, `--muted-foreground` | cards, tables |
| `--primary` | `--primary-foreground` | the one main action per view; brand mark |
| `--secondary` | `--secondary-foreground` | neutral badges, secondary buttons |
| `--muted` | `--foreground` | quiet fills (table head at 50 %, empty-state icon) |
| `--accent` | `--accent-foreground` | hover and the current nav item |
| `--destructive` | `--destructive-foreground` | dangerous actions, errors |
| `--border`, `--input`, `--ring` | (none) | hairlines, control borders, focus halo |
| `--chart-1`…`5` | (none) | chart series only |

`--muted-foreground` on `--muted` is 4.3:1 in light mode, below AA. Don't put
small muted text on a muted fill.

### Section 2: FreeSBC status (extension)

shadcn has no success, warning or info. They are added with the recipe shadcn
uses for `--destructive`: a Tailwind palette step that reads as text, darker
on light and lighter on dark.

| Token | Light / dark | Means |
|---|---|---|
| `--success` | green-700 / green-400 | up, live, valid |
| `--warning` | amber-700 / amber-400 | degraded, high utilisation, retrying |
| `--info` | blue-600 / blue-400 | neutral notice |
| `--destructive` | red-600 / red-400 (shadcn) | down, failed, rejected |
| `--destructive-foreground` | white | text on a destructive fill (shadcn v4 hard-codes `text-white`) |

Rules:

- Status colours mean **state**. Never use one as a chart series or for
  decoration, and never use a chart colour for state.
- State is never colour alone. Always pair it with a word, and usually a dot
  or icon: "81 % in use · high", "Connection lost, retrying…".
- Status colours are for text, icons, dots, thin meters and 6–12 % tints.
  Never fill a large area with one.
- To add a token: put it in section 2 as a `light-dark()` pair, take the
  values from the Tailwind palette, add its pairs to `TestUITokenContrast`.

### Section 3: scale

Tailwind v4 defaults, so a class in a Tailwind codebase maps 1:1.

| Scale | Rule |
|---|---|
| Spacing | `calc(var(--spacing) * n)`, n = the Tailwind number (`* 4` = `p-4` = 16 px). Use 1, 1.5, 2, 2.5, 3, 4, 6, 8, 10. |
| Radius | `--radius-sm/md/lg/xl`. Controls and badges `md`, alerts `lg`, cards `xl`, dots `9999px`. |
| Type | Body `--text-sm` (14 px). Page title `--text-2xl` semibold. Card title `--text-base` semibold. Stat value `--text-2xl` semibold. Captions `--text-xs`. Nothing else. |
| Weight | 400 body, 500 labels and buttons, 600 titles and values. |
| Font | `--font-sans` (system stack) and `--font-mono`. No web fonts: no outside request, and the console must work offline. |
| Shadow | `--shadow-xs` on cards and controls. `--shadow-lg` only for something that floats. |

## Theming

- `color-scheme: light dark` on `:root` means the OS decides.
  `<html data-theme="light|dark">` pins a choice. `theme.js` toggles the
  attribute and stores the choice under `freesbc-theme`.
- Components never use `@media (prefers-color-scheme)` or `[data-theme]`.
  When a component needs a different recipe per theme, use `light-dark()`
  inside the component (see `.btn[data-variant="destructive"]`).
- A derived value that uses `var(--tone)` must be declared on the element
  that sets `--tone`. A custom property resolves its `var()` where it is
  defined, not where it is used.
- Text on a status tint uses the **ink** recipe:
  `light-dark(color-mix(in oklch, var(--tone) 85%, var(--foreground)), var(--tone))`.
  On light, the bare -700 step falls to 3.8–4.4:1 on its own 12 % tint.

## Components

Class names and variants follow shadcn. Variants are attributes
(`data-variant`, `data-size`) rather than modifier classes. This mirrors
shadcn's `cva` variant names and keeps one base class per component.

| Component | Markup | Variants and notes |
|---|---|---|
| Button | `<button class="btn" data-variant="outline" data-size="sm">` | `default` (primary, one per view), `secondary`, `outline`, `ghost`, `destructive`; sizes `sm`, `icon`. Icon first, then label. Icon-only buttons need `aria-label`. |
| Card | `.card > .card-header > .card-heading > .card-title + .card-description`, `.card-action`, `.card-content` (`.flush` for edge-to-edge tables) | The unit of grouping. Don't nest cards. |
| Stat tile | `.card.stat` with `.stat-value`, `.stat-foot` | One number per tile. Put the unit or total in `<small>`. |
| Diff | `pre.diff` of `span.diff-line[data-op]` (`add`, `del`, `ctx`, `skip`, `note`) | Config candidate vs current file. Rows use the badge tint recipe; each added or removed row starts with `+ ` or `- `, so colour is never the only cue. Fill rows with `textContent`. |
| Meter | `.meter[data-level] > span` and `role="meter"` | Width is set from script through `el.style`. Levels: `normal`, `warning` (≥ 80 %), `critical` (≥ 95 %), always with the level in words beside it. |
| Badge | `<span class="badge" data-variant="success">` | `secondary` for counts, `outline` for labels (transports), status variants for state. |
| Table | `.table-wrap > table.table` | Horizontal scroll inside the card, never a squeezed column. `th scope="col"`. |
| List | `ul.list` (`data-layout="grid"` for short lists) | Key/value or label/address rows. |
| Alert | `.alert[data-variant] > svg.icon + .alert-title + .alert-body` | Inline, in place. `role="alert"` only for errors. |
| Banner | `.banner` | Page-wide and persistent: session expired, restart required (restart-only keys changed on disk) and reload failed. Each is its own banner and hidden when it does not apply; the last two follow `reload` in `/api/status`. |
| Empty state | `.empty` | Says what is missing and what will fill it. Never an empty table. |
| Live status | `.status[data-state] > .dot + text` | `live`, `stale`, `expired`; `role="status"`. |

Icons are Lucide (ISC), inlined once as `<symbol>`s in `index.html` and used
through `<svg class="icon"><use href="#i-…"/></svg>`. Size 16 px, stroke 2,
`currentColor`. Add a symbol rather than a new icon source.

## Layout

- One container: max 72rem, 16 px gutters (24 px from 48rem up).
- Page: title and description, then sections 24 px apart. Grids inside a
  section use a 16 px gap.
- The primary content of a view (the calls table) is full width. Secondary
  facts go in stat tiles above or a card below, not in a side column that
  squeezes the table.
- Stat rows use `repeat(auto-fit, minmax(15rem, 1fr))`, so they wrap without
  breakpoints.
- At ≤ 40rem the header stays on one row: the version badge hides, and the
  live text becomes visually hidden but stays readable by screen readers.

## Data display

The data on this console is SIP state, so these rules are the core of
"looks right":

- **Monospace** for anything an operator might copy or compare
  character-by-character: `IP:port`, Call-ID, `fsbc` tokens, transports, config
  keys and file names, versions.
- **Numbers**: `tabular-nums`, right-aligned in tables, thousands separators
  (`8,128`). A ratio shows both sides: `8,128 / 10,000`.
- **Durations**: two units at most (`3d 4h`, `12m 34s`, `47s`).
- **Times**: local `HH:MM:SS` in the cell, the RFC 3339 original in `title`.
- **Truncation**: long identifiers get an ellipsis and their full value in
  `title`. Never wrap a Call-ID.
- **Missing values** render as `—`, never `undefined`, `null` or `NaN`.
- **Stale data stays on screen.** A failed poll marks the header "Connection
  lost, retrying…" and keeps the last good values. Clearing them would turn a
  network blip into a fake outage. `/api/status` and `/api/calls` render
  independently: if only one fails, the other stays current, the failed half
  gets a "Stale" badge and the header says "Partial update, retrying…".
- **Drain is two steps.** The Drain mode card's button only opens an in-page
  confirmation (a destructive-variant `.alert` that names the consequence);
  Confirm sends `POST` or `DELETE /api/drain`. Never `window.confirm`. A poll
  that finds the state changed under an open confirmation closes it.
  `/api/drain` renders independently like the other endpoints.
- **The TLS certificate card** renders `/api/tls` with the other polled endpoints and is hidden while `loaded` is false. Its banner (an `.alert`, warning variant under 30 days, destructive once expired) follows the server's `expired` and `expiring_soon` fields; the 30-day rule lives in the server, not the script. A valid certificate whose file on disk now differs (`disk_differs`) gets the warning banner "Renewed certificate on disk" and the badge "Restart to apply"; when it is also expired or expiring, the expiry title stays and the text says a renewed certificate is already on disk. Long values (SHA-256, the two paths, the Disk row) take a full-width row (`data-wide`) and wrap instead of truncating. Values are set with `textContent`, and a `disk_differs` or `disk_error` row says to restart.
- **Polls never overlap.** The next poll is scheduled with `setTimeout` when
  the previous one has settled, and each request is abandoned after 4 s
  (below the 5 s interval). The session banner clears on the next successful
  response.
- **The State tab** lists `GET /api/registrations`, `/api/carrier-registrations`, `/api/shield/bans`, `/api/switch-nodes` and `/api/carriers` as five cards, each with its own empty state and count badge. It is fetched when opened and on Reload, not polled, and the five requests fail independently (the status line says how many). Registrations have a user search (debounced) and bans show `ban_adds_rejected`; both page 50 at a time with Previous and Next. Times are local `HH:MM:SS` with the RFC 3339 original in `title`; durations use `fmtDuration`; a missing value is `—`. Node and carrier state is a badge with a word (`cooling down`, `failing`), never colour alone. The search box is the `.input` control.
- **The Audit tab** lists `GET /api/audit` (newest first; sign-ins and drain changes) when it is opened and on Reload; it is not polled. Time is local `HH:MM:SS` with the RFC 3339 original in `title`; the result is a badge (`ok` success, anything else warning).
- **The header health badge** shows `GET /api/health`'s status as a word
  (`OK`, `Degraded`, `Critical`, plus the condition count) in the existing
  `success`, `warning` and `destructive` badge variants, so no new token is
  needed, and links to the Health tab. A failed health poll turns it grey
  ("Health: unknown") instead of leaving a stale green.
- **The Health tab** has the Active conditions table (severity badge, id,
  message with optional detail, since) rendered from the Overview poll, and the
  history from `GET /api/health/history` (newest first), fetched when the tab
  opens, on Reload and after each poll while the tab is visible. Empty states
  say so ("No active conditions", "No events"). All API strings go in through
  `textContent`.
- **Restart-only facts say so** where they are shown (listeners, the config
  hint), so nobody expects an edit to rebind a socket.

## Copy

- Sentence case everywhere. No ALL-CAPS headings or column labels.
- Page descriptions are one line that says what the view is for.
- Status text names the state and what to do: "Not valid" with the
  reasons in an alert below.
- Use the SIP and config terms exactly (`Call-ID`, `shield.*`, `${ENV}`);
  don't paraphrase them.

## Accessibility

Contrast is computed, not eyeballed: `TestUITokenContrast` checks every
text/surface pair the components render, in both themes. Current minima:

| Pair | Light | Dark |
|---|---|---|
| muted text on card / table head | 4.73 / 4.53 | 6.91 / 6.39 |
| status text on card | ≥ 4.76 | ≥ 6.19 |
| status ink on its 12 % badge tint (also the config diff's added and removed rows) | ≥ 5.12 | ≥ 5.29 |
| white on destructive button | 4.76 | 6.48 |
| meter fill on its track (non-text, 3:1) | ≥ 3.31 | ≥ 4.63 |

Also:

- One focus style everywhere (`:focus-visible`: 3 px `--ring` at 50 %), plus
  a transparent outline that becomes visible in forced-colours mode.
- Live regions: the header status and config status use `role="status"`;
  validation errors and the session banner use `role="alert"`. A failed validation
  scrolls the "Not valid" alert into view and moves focus to it.
- Every control has a label; icon-only buttons have `aria-label`; decorative
  SVGs have `aria-hidden="true"`.
- `prefers-reduced-motion` disables the live-dot ping and all transitions.

### Known trade-offs (inherited from shadcn, kept for parity)

| Item | Measured | Standard |
|---|---|---|
| `--ring` 50 % focus halo on card | 1.54:1 light, 1.87:1 dark | Meets 2.4.7 (focus visible). Below 3:1 for 2.4.13 (AAA). |
| `--input` border on background | 1.26:1 light, 1.47:1 dark | Below 3:1 for 1.4.11. The textarea is identified by its card, label and content. |

If keyboard-heavy use makes the halo too faint, override it in `ui.css` only
and leave the shadcn tokens alone:
`--focus-ring: 0 0 0 2px var(--background), 0 0 0 4px var(--muted-foreground);`
(≥ 4.7:1).

## Security

- **API data is hostile input.** Call-IDs, peers and listener strings
  originate on the public SIP side. Render them with `textContent` or
  `createElement`, never `innerHTML` or string-built HTML. The admin
  plane serves the unredacted config, so an XSS here leaks every secret in it.
- Nothing inline: no `<script>` body, `<style>`, `style=""` or `on*=`.
  `TestUIHasNoInlineScriptOrStyle` enforces this, because the CSP would
  otherwise drop it silently. Set dynamic styles with `el.style.x = …` (CSSOM
  writes are allowed).
- No request to another origin: no CDN, web font or analytics.
  `connect-src 'self'`.
- `localStorage` holds only the theme choice. Never store API data or the
  config.
- Every response is `Cache-Control: no-store` (`recoverMW`). Don't override
  it per route.

## Checklist for a UI change

1. New colours are tokens in `tokens.css` section 2, with their pairs added
   to `TestUITokenContrast`. `TestUIColoursComeFromTokens` rejects literals
   in `ui.css`.
2. New elements use an existing component, or add one to `ui.css` with
   shadcn's name and variant vocabulary.
3. Spacing, type and radius come from section 3. No new font sizes.
4. Checked in light, dark, a pinned theme opposite to the OS, and at 390 px
   wide.
5. Empty, loading, stale (API down) and error states are all designed.
6. API strings go through `textContent`.
7. `go test -race ./internal/admin` passes. `docs/design.md` §13.7 still
   describes the UI.
