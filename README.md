# STRIDE Threat Modeling Tool

A browser-based tool for **teaching threat modeling**. Students draw a data flow diagram
using the standard legend, annotate each element with a handful of security categories,
export the diagram as an image, and generate a STRIDE report that explains which threats
apply, why, and what to do about them.

No build step, no server, no dependencies — open `index.html` in a browser.

```
git clone <this repo>
cd threat-modeling-tool
open index.html          # macOS;  on Linux: xdg-open index.html
```

Or serve it (handy for a classroom on one machine):

```
npx http-server -p 8080 .
```

The tool starts with a **worked example** — a patient portal, deliberately imperfect, so
the first report a student sees has something to say in every STRIDE category.

---

## The legend

The shapes follow the standard threat-modeling legend:

| Element | Symbol | Represents |
| --- | --- | --- |
| **Entity** | Sharp-cornered rectangle | People, systems or components within the architectural system interface diagram |
| **Process** | Circle or oval | Any running code: compiled programs, scripts, shell commands, SQL, stored procedures |
| **Data store** | Open-ended rectangle, solid lines top and bottom | Files, databases, shared memory, cloud storage, cookies |
| **Data flow** | Line with arrows | Interactions between processes and data movement between entities; arrows show direction |
| **Trust boundary** | Rectangle with a red dashed outline | A boundary of trust between different elements of the diagram |
| **Asset** | Triangle | Something we are protecting, informational or physical |

An asset can be drawn as its own triangle element, or **any** element can be flagged as an
asset in the properties panel, which adds the ▲ marker next to it — both readings of the
legend are supported.

## Using it

### 1. Draw

Pick a shape from the left palette, then click the canvas. Drag to move, drag a corner
handle to resize, drag empty canvas to pan, scroll to zoom. Dragging a trust boundary
moves everything inside it.

To connect two elements: press the **Data flow** tool (or `F`), click the source, then
click the destination. A flow whose endpoints sit in different trust boundaries is drawn
**dashed** and is analysed more strictly — boundary crossings are computed from the
geometry, so moving a box changes the analysis.

Every flow gets **its own connection point** on the border of each element it touches.
Flows are assigned to the side of the shape facing the other end and then spread evenly
along it, ordered so lines don't cross needlessly — several flows into the same element
stay legible instead of piling up on one spot.

**Right-click** an element for its menu: edit properties, draw a data flow from here,
mark as an asset, duplicate, reverse or make a flow bidirectional, and delete. Right-click
empty canvas to add an element at that point or fit the view. Deleting is also available
from the **Delete selected** button under the palette, from the properties panel, and with
the `Del` key.

Keyboard: `V` select · `E` entity · `P` process · `D` data store · `F` flow ·
`B` boundary · `A` asset · `Del` delete · `Esc` cancel · `Ctrl+Z` / `Ctrl+Y` undo/redo ·
`Ctrl+S` save · arrows nudge, `Shift`+arrows nudge by grid.

### 2. Annotate

Select an element and fill in the properties panel:

- **Title** and **description** — shown inside the shape and quoted in the report.
- **Security categories** — the classification and control questions that drive the report.
- **Controls already in place** — free text, printed next to each finding.

The categories differ per element type. Every one of them starts at *not set*, and an
unanswered category is reported as a **coverage gap** rather than assumed to be safe.
That distinction is the point worth making in class: a threat model is only as honest as
its inputs.

| Group | Category | Asked of |
| --- | --- | --- |
| Data | Data classification, Availability need | all elements |
| Classification | Entity kind, Trust level | entities |
| Classification | Exposure, Runtime privilege | processes |
| Classification | Store kind | data stores |
| Classification | Protocol | data flows |
| Classification | Asset kind, Owner | assets and elements |
| Classification | Boundary kind | trust boundaries |
| Controls | Authentication, Authorisation, Logging / audit | most elements |
| Controls | Input validation, Availability controls | processes |
| Controls | Encryption at rest, Integrity controls, Backup / recovery | data stores |
| Controls | Encryption in transit, Message integrity, Throttling | data flows |

### 3. Generate the report

Press **STRIDE report**. The report contains:

1. **Summary** — counts by risk rating and by STRIDE category.
2. **Diagram inventory** — trust boundaries, elements and flows with their annotations.
3. **STRIDE coverage matrix** — element × STRIDE, showing which categories applied and
   how many threats were raised, so students can see the systematic sweep.
4. **Threats and mitigations** — each finding with its STRIDE category, the security
   property it violates, a risk rating, the threat in plain language, and concrete
   mitigations.
5. **Coverage gaps** — the questions nobody answered.
6. **Appendices** — a STRIDE reference table and an explanation of the risk rating.

Download it as **Markdown**, **HTML**, or **CSV** (one row per threat, drops straight into
a risk register), or print to PDF.

### 4. Score the threats

Two scoring routes, and they can be mixed.

**Your own severity scale.** Press **Scoring…** to see how severity is computed and to
import a profile of your own — your severity names, colours, thresholds, per-category
weights and per-rule overrides. Download the annotated template from the same dialog for a
starting point. The profile is stored inside the threat model file, so a class or a team
all score the same way, and the report's Appendix B prints the arithmetic in full.

```jsonc
{
  "name": "ACME three-tier scale",
  "levels": [                                   // mapped from the computed score
    { "label": "Note",     "color": "#7d8ba6", "min": 0   },
    { "label": "Issue",    "color": "#cbb01f", "min": 3   },
    { "label": "Escalate", "color": "#c62828", "min": 4.5 }
  ],
  "baseScores":       { "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 6 },
  "categoryPoints":   { "I": 0.5, "E": 0.5 },   // weight STRIDE categories differently
  "aggravatorPoints": { "sensitiveData": 0.5, "externalExposure": 0.5,
                        "markedAsset": 0.5, "safetyCriticalDoS": 0.5 },
  "mitigatorPoints":  { "publicData": 0.5, "lowAvailabilityNeed": 0.5 },
  "ruleScores":       { "ds-i-rest": 6 },       // override individual rules by id
  "cvss":             { "useWhenPresent": true }
}
```

Score = base rating of the rule + category points + aggravating context − mitigating
context, mapped onto the highest level whose `min` it reaches. Invalid profiles are
rejected with a specific reason rather than silently half-applied, and a bad profile inside
a model file never stops the file from opening.

**CVSS v4.0.** Any individual threat in the report can carry a CVSS v4.0 assessment. Build
the vector in the [NVD CVSS v4.0 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator),
then paste the vector and the score it produced into the finding, with an optional note on
how it was rated. The vector is validated metric by metric against the v4.0 specification
(all eleven mandatory base metrics, plus threat, environmental and supplemental metrics);
the numeric score is taken as entered. Its band — None, Low, Medium, High, Critical —
replaces the modelled severity, which you can turn off under **Scoring…** if you would
rather keep both views. Vectors, scores and notes are saved with the model and appear in
the Markdown, HTML and CSV exports.

This tool deliberately does not reimplement the CVSS 4.0 scoring tables: the score comes
from the official calculator, so there is no second, subtly-different implementation to
disagree with it.

### 5. Export the picture

**Export PNG** (2× resolution) or **Export SVG** writes the diagram, its title and the
legend to an image. The grid and selection handles are never included.

### 6. Save

The diagram is autosaved to browser storage. **Save .json** writes a portable file to hand
to students or commit to a repository; **Open…** loads it back. `examples/patient-portal.json`
is the worked example.

---

## The methodology

STRIDE, applied **per element**. Each element type is only analysed for the categories
that can apply to it:

| Letter | Threat | Property violated | Applies to |
| --- | --- | --- | --- |
| **S** | Spoofing | Authentication | Entity, Process |
| **T** | Tampering | Integrity | Process, Data store, Data flow, Asset |
| **R** | Repudiation | Non-repudiation | Entity, Process, Data store |
| **I** | Information disclosure | Confidentiality | Process, Data store, Data flow, Asset |
| **D** | Denial of service | Availability | Process, Data store, Data flow, Asset |
| **E** | Elevation of privilege | Authorisation | Process |

Trust boundaries are context rather than a target: they are not analysed directly, they
raise the risk of every flow that crosses them.

Some threats belong to an element but are only visible on a flow — an unauthenticated
inbound call, for example, is a *spoofing* problem for the process receiving it. Those
findings are attached to the receiving element and cite the flow they came in on.

### How risk is rated

Each rule carries a base rating, adjusted by diagram context. Aggravating factors are:
confidential or regulated data; an internet-facing or anonymous-facing element, or a flow
crossing an external boundary; the element being marked as an asset; and, for
denial-of-service, a safety-critical availability need. Under the built-in scale two of
those raise the rating one step, and **Critical** is reserved for threats critical in
themselves or carrying three; public data or a low availability need lowers it one. All of
those numbers are editable — see *Score the threats* above. The ratings are a starting
point for discussion, not a substitute for a risk acceptance process — which is itself
worth saying out loud in class.

---

## Teaching with it

A workable 90-minute session:

1. **Legend first (10 min).** Open the example, walk the six shapes, toggle the legend on
   the diagram.
2. **Draw together (20 min).** Build a diagram of a system the group knows. Insist on
   descriptions — "what does this actually do?" surfaces more than the shapes do.
3. **Boundaries (10 min).** Add trust boundaries and watch which flows go dashed. Ask
   what changes when a box moves across a boundary.
4. **Annotate in pairs (20 min).** Half the room fills in one subsystem, half another.
   The arguments about *which* option to pick are the learning.
5. **Report (20 min).** Generate it, sort by risk, and challenge the ratings — the tool is
   wrong about something, and finding out why is the exercise.
6. **Gaps (10 min).** Section 5 lists everything nobody answered. Discuss what it would
   take to answer them, and who would have to be in the room.

---

## Project layout

```
index.html            app shell and layout
css/styles.css        application chrome (the diagram styles itself inline, so exports are self-contained)
js/model.js           data model, the category catalogue, save/load, undo history
js/stride.js          STRIDE knowledge base, rule catalogue and the analysis engine
js/diagram.js         SVG canvas: shapes, direct manipulation, SVG/PNG export
js/report.js          HTML / Markdown / CSV report generation
js/app.js             UI wiring, properties panel, file IO, worked example
examples/             saved threat models
```

### Adding or changing rules

Rules live in one array in `js/stride.js`:

```js
{
  id: 'ds-i-rest', types: ['datastore'], cat: 'I', risk: 'high',
  test: function (el) { return sensitive(el) && weakOrUnset(el, 'encryptionAtRest', 'None'); },
  title: 'Sensitive data stored unencrypted in {name}',
  threat: 'The contents of {name} are readable to anyone who obtains …',
  mitigations: ['Encrypt at rest with keys held in a managed KMS …']
}
```

`test` receives the element and a context object (`impact`, `exposureScore`, `crossings`,
`isAsset`). `{name}` is replaced with the element's title and `{n}` with the boundaries it
crosses. Adding a new category to ask about is a matter of appending to `TM.FIELDS` in
`js/model.js` — the properties panel, the report and the coverage gap list all build
themselves from that catalogue.

A rule's `id` is also its handle in a scoring profile's `ruleScores`, so a rule can be
re-rated without touching the code. Rule ids are included in the CSV export.

### Teaching sessions to add

The scoring profile and CVSS features open up two more exercises worth 20 minutes each:
have the group write a profile that reflects how their organisation actually escalates
things, or take the three worst findings and score them properly in the NVD calculator,
then compare the CVSS band against the modelled rating and work out which one is telling
the truth.

## Browser support

Any current Chrome, Edge, Firefox or Safari. Uses pointer events, SVG and the File API;
no network access at any point, so nothing about the modelled system leaves the machine.
