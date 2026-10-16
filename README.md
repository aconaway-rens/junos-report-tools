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
| **Policies** | Ordered per zone pair, with addresses and applications resolved through the address book, and what each policy logs — including logging inherited from config groups |
| **VPN** | `security ipsec vpn` joined to its gateway, policies and proposals, alongside live IKE and IPsec state |
| **Flow** | Would this flow pass? Writes the `show security match-policies` command, then reads the device's answer back against the config |
| **Logging** | Where session logs go — `security log` streams and `system syslog` destinations, each with the interface and zone it leaves by — and what each policy logs (session-init, session-close, drops) |

Both config forms are read — curly-brace and `| display set` — and you can mix them.

### Getting everything in one go

Under the box is a block of commands with a **Copy all commands** button:

```
set cli screen-length 0
set cli screen-width 1024
show configuration | display inheritance
show route
show security ipsec security-associations detail
show security ike security-associations detail
show security policies hit-count
```

Paste it into the SSH session and copy everything it prints, prompts included, into the
box, or save the session log and open it. The two `set cli` lines turn off paging and line
wrapping for that session only, so nothing is cut at `---(more)---` or split across lines.
The prompt lines matter: they are how the page tells one command's output from the next.

A saved terminal log is read the same as a paste. The byte-order mark, CRLF line endings,
NUL padding, terminal escape codes, backspaces and leftover pager prompts are cleaned up
first. A file too big to edit in the box (over about 4 MB) is still parsed in full.

### Config groups

`apply-groups` is taken into account. `show configuration | display inheritance` has the
device write the inherited statements out in place, and that is the authoritative answer.
For a plain `show configuration`, groups are expanded here the way Junos does it:
wildcards such as `<*>` match only names the configuration already has, an explicitly
configured value wins over an inherited one, an earlier group wins over a later one,
`apply-groups` below the top applies only to that part of the config, and
`apply-groups-except` is honoured. `${node}` is not expanded, because which node it means
depends on the box. Groups that are applied nowhere are reported.

### Optional operational output

The configuration is what the box is meant to do. These say what it is actually doing:

- `show route`
- `show security ipsec security-associations detail`
- `show security ike security-associations detail`
- `show security policies hit-count`

There is one box. Paste them into it with the configuration, in any order, or leave them
out. A session capture or an RSI already holds them. A checklist under the box lists the
commands, each with a copy button, and ticks off each one it found with a count. Drop or
open several files at once and they are all added; a file dropped onto a box that already
holds something is appended to it. A capture pasted twice is counted once.

Where a live capture overlaps the configuration the live one wins, **and the difference is
reported**: a static route that never made it into the RIB, a phase 1 that came up on
algorithms the proposals merely allowed, a tunnel negotiated at phase 1 with no phase 2
behind it.

### Testing a flow

The **Flow** view takes a source, destination, port and protocol, fills in the zones from
the routes, and writes the `show security match-policies` command for you. Run it on the
box, paste what it printed, and the answer is read back against the configuration:
which address and application entries the flow fell inside, a policy the device matched
that the config paste does not have, a deny sitting ahead of a permit that would have
passed the flow, a permit into a tunnel that is down, cluster nodes that disagree.

The device makes the decision, not this page. Predefined `junos-*` applications and
groups expanded here without the device's own `display inheritance` are only an
approximation, so a verdict worked out locally would only be a plausible guess.

### Logging

Where a session log goes depends on `security log mode`. In **stream** mode the data plane
sends it straight to each `security log stream` host and system syslog never sees it; in
**event** mode it goes to the routing engine and out through `system syslog`. The Logging
view reads both hierarchies and tags each destination with whether it carries session
logs, and why not when it doesn't. Each log host's address goes through the same
route → interface → zone lookup as everything else, so you can see which way the logs leave.

Paste `show security policies hit-count` and each policy also shows how many lookups hit
it. A deny that logs nothing becomes "48,211 lookups hit this deny, none logged".

Logging inherited through `apply-groups` is a common way to turn on `session-close`
everywhere, so it is applied, and each log flag and destination that came from a group
says which one. A group that sets policy logging but reaches no policy (applied nowhere,
or its wildcards match nothing) is a warning, since the policies it was meant for do not
log.

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
- policies that ask for session logs when nothing receives them, a stream filtered above
  `info`, a stream that can only leave through `fxp0`, stream mode with no source address,
  and streams configured while the mode is `event`
- `session-close` on a deny (it never fires — only `session-init` records a drop), and
  zone pairs whose fall-through to the default policy is dropped without a log

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
