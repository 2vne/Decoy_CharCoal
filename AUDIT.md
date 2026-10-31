# SENTINEL SOC - FRONTEND CLICKABLE ELEMENTS AUDIT

Date: 2026-10-31
Scope: Full review of all buttons, links, filters, tabs, and interactive elements across all 9 pages and components.

---

## 1. Global Navigation & Header (Layout.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Brand Logo / Title | Sidebar | No (static) | No | N/A | No | WORKS | Header badge only, not a link |
| Nav: Overview | Sidebar | Yes (`NavLink`) | No | N/A (client route `/`) | Yes (navigates) | WORKS | Route `/` renders Overview |
| Nav: Live Events | Sidebar | Yes (`NavLink`) | No | N/A (client route `/events`) | Yes (navigates) | WORKS | Route `/events` renders LiveEvents |
| Nav: Attackers | Sidebar | Yes (`NavLink`) | No | N/A (client route `/attackers`) | Yes (navigates) | WORKS | Route `/attackers` renders AttackersPage |
| Nav: Threat Universe | Sidebar | Yes (`NavLink`) | No | N/A (client route `/universe`) | Yes (navigates) | WORKS | Route `/universe` renders UniversePage |
| Nav: Relationship Graph | Sidebar | Yes (`NavLink`) | No | N/A (client route `/relationships`) | Yes (navigates) | WORKS | Route `/relationships` renders RelationshipsPage |
| Nav: Honeypots | Sidebar | Yes (`NavLink`) | No | N/A (client route `/honeypots`) | Yes (navigates) | WORKS | Route `/honeypots` renders Honeypots |
| Nav: Incidents | Sidebar | Yes (`NavLink`) | No | N/A (client route `/incidents`) | Yes (navigates) | WORKS | Route `/incidents` renders IncidentsPage |
| Nav: Response Center | Sidebar | Yes (`NavLink`) | No | N/A (client route `/response`) | Yes (navigates) | WORKS | Route `/response` renders ResponseCenterPage |
| Nav: Reports | Sidebar | Yes (`NavLink`) | No | N/A (client route `/reports`) | Yes (navigates) | WORKS | Route `/reports` renders ReportsPage |
| "LAUNCH ATTACK" Toggle | Sidebar Bottom | Yes (`setSimMenuOpen`) | No | N/A | Yes | WORKS | Toggles scenario popover |
| Scenario: Full Kill Chain | Sidebar Popover | Yes (`handleSimulate`) | Yes | `POST /api/simulate/start` (200) | Yes (sim starts) | WORKS | Starts scenario |
| Scenario: SSH Brute Force | Sidebar Popover | Yes (`handleSimulate`) | Yes | `POST /api/simulate/start` (200) | Yes | WORKS | Starts scenario |
| Scenario: Noise Mass Scanner | Sidebar Popover | Yes (`handleSimulate`) | Yes | `POST /api/simulate/start` (200) | Yes | WORKS | Starts scenario |
| Scenario: Repeat Attacker | Sidebar Popover | Yes (`handleSimulate`) | Yes | `POST /api/simulate/start` (200) | Yes | WORKS | Starts scenario |
| Scenario: 3-IP Syndicate | Sidebar Popover | Yes (`handleSimulate`) | Yes | `POST /api/simulate/start` (200) | Yes | WORKS | Starts scenario |
| Toast Notification System | Top/Global | No | No | N/A | No | **BROKEN** | Missing visual toast notifications for async actions and errors |
| Universe Keyboard Shortcut | Global | No | No | N/A | No | **BROKEN** | No shortcut to jump to Threat Universe |

---

## 2. Overview Page (Overview.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| "RUN FULL APT DEMO" Button | Header | Yes (`runSimulation`) | Yes | `POST /api/simulate/start` (200) | Partial | **BROKEN** | No loading state or toast; narrator overlay missing |
| Active Attackers Card | KPI Grid | Yes (`navigate('/attackers')`) | No | Client route | Yes | WORKS | Navigates to Attackers |
| Critical Threats Card | KPI Grid | Yes | No | Client state | Partial | **BROKEN** | If `criticalAttackers` empty, navigates, but does not show loading/toast; should open dossier |
| Events Today Card | KPI Grid | Yes (`navigate('/events')`) | No | Client route | Yes | WORKS | Navigates to Live Events |
| Honeypots Fleet Card | KPI Grid | Yes (`navigate('/honeypots')`) | No | Client route | Yes | WORKS | Navigates to Honeypots |
| "FULLSCREEN VIEW" Button | Above Canvas | Yes (`navigate('/universe')`) | No | Client route | Yes | WORKS | Navigates to Universe |
| Recent Incident Row | Incident Box | Yes (`setSelectedAttackerId`) | Yes (loads attacker) | `GET /api/attackers/{id}` | Yes | WORKS | Opens attacker dossier drawer |
| "VIEW INCIDENT QUEUE" Button | Incident Box | Yes (`navigate('/incidents')`) | No | Client route | Yes | WORKS | Navigates to Incidents |

---

## 3. Live Events Page (LiveEvents.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Pause / Resume Stream Button | Header | Yes (`setIsPaused`) | No | Local state only | Partial | **BROKEN** | Context WebSocket listener keeps appending events even if paused! `isPaused` not respected in Context |
| Search Input | Filter Bar | Yes (`setSearchTerm`) | No | Client-side filter | Yes | WORKS | Filters events |
| Honeypot Filter Dropdown | Filter Bar | Yes (`setSelectedHoneypot`)| No | Client-side filter | Yes | WORKS | Filters by honeypot |
| Severity Filter Dropdown | Filter Bar | Yes (`setSelectedSeverity`)| No | Client-side filter | Yes | WORKS | Filters by severity |
| Chevron / Row Click (Expand) | Table Rows | Yes (`toggleRow`) | No | Client state | Yes | WORKS | Expands row |
| Source IP Button | Table Rows | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens dossier if attackerId known |
| "NORMALISED JSON" Button | Inspector | Yes (`setViewMode`) | No | Client state | Yes | WORKS | Toggles normalized view |
| "RAW LOG" Button | Inspector | Yes (`setViewMode`) | No | Client state | Yes | WORKS | Toggles raw log view |

---

## 4. Attackers Page (AttackersPage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Search Input | Filter Bar | Yes (`setSearch`) | No | Client filter | Yes | WORKS | Filters attacker list |
| Band Filter Buttons (all/crit/etc)| Filter Bar | Yes (`setBandFilter`)| No | Client filter | Yes | WORKS | Filters list by band |
| Table Row Click | Table Rows | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens investigation drawer |
| "BLOCK" Button | Table Action | Yes (`blockAttacker`) | Yes | `POST /api/attackers/{id}/block` | Yes | **BROKEN** | No loading spinner on button, no success/error toast |
| "UNBLOCK" Button | Table Action | Yes (`unblockAttacker`) | Yes | `POST /api/attackers/{id}/unblock` | Yes | **BROKEN** | No loading spinner on button, no success/error toast |
| Open Dossier Chevron | Table Action | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens drawer |

---

## 5. Threat Universe & UniversePage (ThreatUniverse.jsx, UniversePage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Mouse Wheel Zoom | Canvas | No | No | N/A | No | **BROKEN** | Canvas has no wheel zoom listener; scale is locked at 1.0x |
| Mouse Drag Pan | Canvas | No | No | N/A | No | **BROKEN** | Canvas has no drag/pan listener |
| Double Click to Reset View | Canvas | No | No | N/A | No | **BROKEN** | Missing double-click reset |
| Zoom In / Out Buttons (+ / - / Reset)| Canvas HUD | No | No | N/A | No | **BROKEN** | No zoom controls in the UI |
| Canvas Planet Hit-Testing | Canvas | Yes (`handleMouseMove`) | No | N/A | Flaky / **BROKEN** | Coordinate transform does not account for zoom/pan; hit radius was only 18px on unzoomed coordinates |
| Planet Click | Canvas | Yes (`handleClick`) | Yes | `GET /api/attackers/{id}` | Flaky / **BROKEN** | Doesn't smoothly zoom/center on planet before opening; misses clicks when moving fast |
| Orbit Lines & Rings | Canvas | Yes | No | N/A | Yes | WORKS | Labeled orbit rings rendered |
| Relationship Edges between planets | Canvas | Yes (partial) | No | N/A | **BROKEN** | Edge rendering fails when attacker IDs mismatch IP keys; no relationship toggle; no edge click evidence modal |
| Searchable Attacker List Sidebar | Threat Universe | No | No | N/A | No | **BROKEN** | Missing left-side searchable attacker selector |
| Filter Buttons (all/crit/etc) | Canvas HUD | Yes (`setActiveBandFilter`) | No | Client filter | Yes | WORKS | Filters planets |
| "FULLSCREEN UNIVERSE" Button | Preview HUD | Yes (`onExpand`) | No | Client route | Yes | WORKS | Expands to full page |

---

## 6. Relationship Graph Page (RelationshipsPage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Entire Page Visualization | Page Body | No (renders cards) | Yes | `GET /api/relationships` | Cards | **BROKEN** | Requirement: "Relationship Graph is a table, not an interactive graph. Replace with interactive force graph." |
| Attacker A Link | Edge Card | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens dossier |
| Attacker B Link | Edge Card | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens dossier |

---

## 7. Honeypot Fleet Page (Honeypots.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Fleet Card Click | Card Grid | Yes (`setActiveDrawerHp`)| No | Local state | Partial | **BROKEN** | `activeDrawerHp` is set, but drawer markup is NOT rendered in `Honeypots.jsx`! Card click does nothing visible! |
| Drawer Close Button | Drawer | Missing | No | N/A | No | **BROKEN** | Drawer component wasn't rendered |

---

## 8. Incident Response Center (IncidentsPage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Incident Ticket Click | Left Queue | Yes (`setSelectedIncident`) | No | Local state | Yes | WORKS | Switches active incident |
| Status Change Buttons (new/investigating/etc)| Detail Header | Yes (`handleStatusChange`) | Yes | `PATCH /api/incidents/{id}` | Yes | WORKS | Updates incident status |
| "View Attacker Dossier" Link | Detail Header | Yes (`setSelectedAttackerId`)| Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens dossier |
| "ADD NOTE" Button | Notes Box | Yes (`handleAddNote`) | Yes | `POST /api/incidents/{id}/notes`| Yes | WORKS | Appends note |
| "DOWNLOAD REPORT PDF" Button | Detail View | No | No | Missing API call | No | **BROKEN** | No button on IncidentsPage to call `GET /api/incidents/{id}/report` |
| AI Investigation Card | Detail View | No | No | Missing API call | No | **BROKEN** | No card displaying AI investigation with evidence links |
| Evidence Chain of Custody Badge | Detail View | No | No | Missing API call | No | **BROKEN** | No cryptographic integrity badge shown |

---

## 9. Response Center Page (ResponseCenterPage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Filter Buttons (all/active/rolled_back)| Top Bar | Yes (`setFilter`) | No | Local filter | Yes | WORKS | Filters blocks table |
| Target IP Click | Table Rows | Yes (`setSelectedAttackerId`) | Yes | `GET /api/attackers/{id}` | Yes | WORKS | Opens dossier |
| "ROLLBACK" Button | Table Rows | Yes (`unblockAttacker`) | Yes | `POST /api/attackers/{id}/unblock` | Yes | WORKS | Rolls back block |
| Actions Approval Queue (Approve/Reject)| Page Body | No | No | Missing API call | No | **BROKEN** | Does not read `GET /api/actions` or allow approve/reject of proposed actions! |
| What-If Counterfactual Simulator Panel | Page Body | No | No | Missing API call | No | **BROKEN** | Missing what-if comparison panel |
| IOC Export Buttons (JSON, CSV, STIX) | Page Body | No | No | Missing API call | No | **BROKEN** | Missing export buttons for `GET /api/ioc` |

---

## 10. Attacker Investigation Drawer (AttackerInvestigation.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| Close Drawer (X) | Header | Yes (`onClose`) | No | Local callback | Yes | WORKS | Closes drawer |
| Tabs (Profile, Risk, Timeline, etc)| Header Tabs | Yes (`setActiveTab`) | No | Local state | Yes | WORKS | Switches tab |
| "BLOCK IP" Button | Profile / Actions | Yes (`blockAttacker`) | Yes | `POST /api/attackers/{id}/block` | Yes | WORKS | Enforces block |
| "UNBLOCK IP" Button | Profile / Actions | Yes (`unblockAttacker`) | Yes | `POST /api/attackers/{id}/unblock` | Yes | WORKS | Enforces unblock |
| Replay Play / Pause | Replay Tab | Yes (`setIsPlaying`) | No | Timer loop | Yes | WORKS | Starts / stops typing |
| Replay Reset | Replay Tab | Yes (`setReplayIndex(0)`) | No | Local state | Yes | WORKS | Resets to beginning |
| Replay Speed Buttons (0.5x, 1x, 2x)| Replay Tab | Yes (`setReplaySpeed`)| No | Local state | Yes | WORKS | Changes delay speed |
| MITRE Technique Expansion Chevron | MITRE Tab | Yes (`setExpandedTechId`)| No | Local state | Yes | WORKS | Toggles evidence dropdown |
| Related Attacker IP Click | Related Box | Yes (`setSelectedAttackerId`)| Yes | `GET /api/attackers/{id}` | Yes | WORKS | Switches dossier |

---

## 11. Reports Page (ReportsPage.jsx)

| Element | Location | Handler Exists? | API Call Made? | Endpoint & Return Code | UI Updates? | Status | Reason / Issue Found |
|---|---|---|---|---|---|---|---|
| "EXPORT PDF" Button | Top Right | Yes (`window.print()`) | No | N/A | Browser print | Partial | Works via browser print dialog, but backend PDF exists |
| Executive Summary API Data | Page Body | No | No | `GET /api/reports/summary` | No | **BROKEN** | Uses legacy metrics instead of rich `/api/reports/summary`, exposure gauges, or health correlation |
| Security Exposure Budget Gauges | Page Body | No | No | `GET /api/exposure` | No | **BROKEN** | Missing interactive exposure budget gauges |
| Health Correlation Chart | Page Body | No | No | `GET /api/health-correlation` | No | **BROKEN** | Missing burst correlation chart |

