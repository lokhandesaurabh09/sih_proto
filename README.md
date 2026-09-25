# CII Predictive SOC Engine

AI-powered attack forecasting dashboard prototype for a Smart India Hackathon concept demo.

> Prototype scope: This is a frontend-only user experience mockup. All predictions, alerts, and mitigation outputs are simulated from hardcoded scenario data. There is no real ML model or backend service behind this repository.

## Overview

This dashboard presents a single attack scenario — The SSH Brute Force — as an end-to-end security workflow that demonstrates the full predict → alert → mitigate loop.

### Included experience

- Predictive risk timeline showing a world-model P(infiltration) curve versus a baseline classifier, with a threshold at 0.75
- Critical alert generation when risk crosses the threshold, including the predicted ATT&CK stage, target node, and one-click isolation action
- MITRE ATT&CK tracker highlighting the current kill-chain stage and the next predicted stage
- SHAP-based feature importance panel illustrating which network signals drive the forecast
- Human-in-the-loop firewall mitigation flow, where the AI drafts a DROP rule and an operator approves or arms it
- Live telemetry feed showing packet activity with statuses such as normal, suspicious, malicious, FW·DROP, and system
- Manual ACL builder with validated IPv4/CIDR and port input, duplicate prevention, 12-rule cap enforcement, and rule deployment
- Policy export to a JSON file named cii-acl-policy-< timestamp >.json

## Tech stack

| Layer    | Technology        |
| ---------| ------------------|
| Runtime  | React 18 + Vite 5 |
| Styling  | Tailwind CSS 3    |
| Charts   | Recharts          |
| Animation| framer-motion     |
| Icons    | lucide-react      |

## Getting started

```bash
# install dependencies
npm install

# start the dev server at http://localhost:5173
npm run dev

# create a production build
npm run build

# preview the production build
npm run preview
```

This project requires Node.js and npm. The fonts used, Inter and JetBrains Mono, are loaded from Google Fonts at runtime.

## Project structure

```text
├── index.html                     # app entry page with dark theme
├── package.json
├── vite.config.js                # Vite configuration and dev server setup
├── tailwind.config.js            # Tailwind setup and custom animations
├── postcss.config.js
├── README.md
└── src
    ├── main.jsx                  # application entry point
    ├── index.css                 # Tailwind directives and base styling
    ├── App.jsx                   # dashboard flow: timeline, alerts, MITRE tracker, SHAP, and feed
    └── FirewallMitigator.jsx     # mitigation workflow, ACL builder, rule arm/disarm, and export
```

## How the simulation works

- A tick timer with TICK_MS = 2200ms advances a hardcoded scenario timeline and generates ambient network traffic with randomized states
- When P(infiltration) crosses the configured threshold, the alert lifecycle runs and the mitigation module drafts FW-AUTO-001
- DROP rules are enforced against incoming traffic statuses through a shared reference; detected hostile packets become FW·DROP rows and increment the rule hit count
- The main risk chart responds to mitigation state: armed mode projects a fall in risk, while revoked mode shows risk climbing again

All logic runs entirely on the client side in the browser. Refreshing the page resets the simulation.

## Known limitations

- No backend, database, or authentication layer
- No real ML model: predictions, SHAP values, and confidence scores are display-only values from hardcoded arrays
- Single fixed scenario: SSH brute force attack only
- No persistence beyond the exported client-side ACL policy JSON
- This is designed as a UI/UX prototype rather than a production-ready security system
