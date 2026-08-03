# Network Report Tools

Browser-based tools for turning network CLI output into readable reports.

## Included tools

- `ipsec-sa-report.html` (v1.0) for IPsec security-association summaries
- `zone-route-report.html` (v1.1) for zone and route correlation reports
- `policy-report.html` (v1.0.1) for security policy reports

These files are designed to run locally in a browser from a local file path and do not upload data anywhere.

## What's new

### zone-route-report v1.1

- **Diagram view.** Renders a generic device with one port per bound interface, wired
  out to each security zone. Each interface gets its own box holding just the routes
  that egress it; all of a zone's interface boxes are grouped inside the zone container.
  Interfaces that belong to no zone collect into an "Unzoned egress" group.
- **Colour by link type.** Connectors and interface boxes are coloured by interface kind
  (ethernet, reth/ae, tunnel, mgmt, other); zone containers carry zone state (functional,
  unzoned/conflict, no interfaces).
- **Download SVG.** The diagram exports as a self-contained `.svg` — no external
  references, consistent with the offline, nothing-uploaded design of these tools.
