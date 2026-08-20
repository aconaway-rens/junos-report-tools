# Junos Config Report

One HTML file that turns a Junos configuration into a readable report, in the browser,
with nothing uploaded anywhere.

Open [`junos-config-report.html`](junos-config-report.html) from your filesystem — double
click it, or copy it onto a jump host and open it there. Paste a configuration, or drop a
file on it. That is the whole setup.

## Why

Answering "what egresses this zone", "which policy is actually matching", or "why is this
tunnel down" means holding several config hierarchies in your head at once and joining
them by hand. This does the joins.

## What it reports

| View | Answers |
|---|---|
| **Overview** | What is in the config, section by section, plus the findings that cut across sections |
| **Interfaces** | Every logical unit with its address, family, VLAN, zone and routing instance |
| **Zones** | Each zone with its interfaces and the routes that egress them |
| **Routes** | The route table, with where each route came from |
| **Diagram** | A device wired out to each zone, one route box per interface — downloads as SVG |
| **Policies** | Ordered per zone pair, with addresses and applications resolved through the address book |
| **VPN** | `security ipsec vpn` joined to its gateway, policies and proposals, alongside live IKE and IPsec state |

Both config forms are read — curly-brace and `| display set` — and you can mix them.

### Optional operational output

The configuration is what the box is meant to do. Three optional panes take what it is
actually doing:

- `show route`
- `show security ipsec security-associations detail`
- `show security ike security-associations detail`

Paste them, drop a file on them, or ignore them. If you pasted a whole session capture or
an RSI into the configuration box then they are already in there, and the panes say so
rather than leaving you to paste it twice. Supply the same capture in both places and it is
counted once. However you divide the input, the report comes out the same.

Where a live capture overlaps the configuration the live one wins, **and the difference is
reported**: a static route that never made it into the RIB, a phase 1 that came up on
algorithms the proposals merely allowed, a tunnel negotiated at phase 1 with no phase 2
behind it.

## What it will not do

**It will not invent a value.** If Junos did not print something, the report shows a dash.
You are troubleshooting; a plausible-looking fabricated value is worse than a blank.

Routes marked `config` are the static routes plus the connected routes implied by each
interface address. Their egress interface is worked out by matching the next-hop against
the configured connected subnets, exactly as the device would for a directly attached next
hop. That is *intent*, not the live RIB — routes learned by OSPF, BGP or anything else
appear only if `show route` is pasted in, and those rows are marked `show route`. A
next-hop falling outside every configured subnet is reported unresolved rather than
attributed to a plausible-looking interface.

**Pre-shared keys and other inline secrets are dropped as the configuration is parsed**, so
they reach neither the report nor its exports.

## Findings

Things it will tell you about, rather than making you notice:

- an interface bound to two zones, or to a zone that never defines it
- a zone with interfaces but no route reaching it
- a policy made unreachable by an earlier catch-all in the same zone pair
- a policy referencing an address name that is not in the address book
- an `st0` unit that is in no security zone
- deprecated crypto, aggressive mode, missing PFS — in the proposals *and* in what phase 1
  actually negotiated
- a static next-hop that resolves nowhere
- dynamic routing protocols whose routes are, by definition, not in the config

## Exports

Every view exports to CSV and copies as Markdown. The diagram downloads as a
self-contained `.svg`.

## Privacy

Production firewall configuration goes into this thing, so:

- **One file.** All HTML, CSS and JS inline. No imports, no bundler, no build step.
- **Zero runtime dependencies.** No CDN, no fonts, no analytics, no network call of any kind.
- **No browser storage.** No `localStorage`, `sessionStorage`, `IndexedDB` or cookies.
- **Works from `file://`.** A file you open is read in the browser and never leaves it.

"Runs entirely in this page. Nothing is uploaded." is meant literally.

## Tests

```
npm install
npm test
```

The tests load the page with jsdom, click through the real UI, and assert on rendered DOM
as well as on the parsers. The tool itself has no dependencies; jsdom is only for the test
harness.

## Verify before you trust it

Built and tested against constructed fixtures, not live devices. Field names, labels and
output formats drift across Junos releases and platforms. Check it against real captures
from the platform you care about before relying on it, and widen the patterns where it
comes up short.

## History

This began as three separate tools, one per command — `ipsec-sa-report.html`,
`zone-route-report.html` and `policy-report.html`. `junos-config-report.html` covers all
three from a single input and replaces them. The originals are in the git history if you
want them back.
