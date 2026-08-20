/*
 * Test harness for junos-config-report.html.
 *
 *   npm install
 *   npm test          (or: node tests/run.js)
 *
 * The page is loaded with jsdom (runScripts: "dangerously"), driven through the
 * real UI, and asserted on the rendered DOM as well as on the parsers exposed on
 * window. A window "error" listener collects anything the page throws.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const ROOT = path.join(__dirname, "..");

let passed = 0;
const failures = [];
let group = "";

function describe(name, fn){
  group = name;
  try { fn(); }
  catch(e){ failures.push({ group, name: "(setup)", err: e }); }
  group = "";
}
function it(name, fn){
  try { fn(); passed++; }
  catch(e){ failures.push({ group, name, err: e }); }
}
function ok(cond, msg){
  if(!cond) throw new Error(msg || "expected truthy");
}
function eq(a, b, msg){
  const sa = JSON.stringify(a), sb = JSON.stringify(b);
  if(sa !== sb) throw new Error((msg ? msg + ": " : "") + `expected ${sb}, got ${sa}`);
}
function includes(hay, needle, msg){
  if(String(hay).indexOf(needle) === -1){
    throw new Error((msg ? msg + ": " : "") + `expected to find ${JSON.stringify(needle)} in ${JSON.stringify(String(hay).slice(0, 400))}`);
  }
}
function excludes(hay, needle, msg){
  if(String(hay).indexOf(needle) !== -1){
    throw new Error((msg ? msg + ": " : "") + `did not expect to find ${JSON.stringify(needle)}`);
  }
}

/* ---------------------------------------------------------------- loading -- */

function load(file){
  const html = fs.readFileSync(path.join(ROOT, file), "utf8");
  const errors = [];
  const dom = new JSDOM(html, { runScripts: "dangerously", url: "file:///tools/" + file });
  dom.window.addEventListener("error", e => errors.push(String(e.error || e.message)));
  const $ = id => dom.window.document.getElementById(id);
  return { dom, window: dom.window, doc: dom.window.document, $, errors,
           text: id => ($(id) ? $(id).textContent : "") };
}

/* ================================================================ FIXTURES == */

const BRACE_ZONES = `
security {
    zones {
        security-zone trust {
            description "Internal";
            interfaces {
                reth0.0 {
                    host-inbound-traffic {
                        system-services {
                            ping;
                        }
                    }
                }
                reth0.100;
            }
        }
        functional-zone management {
            interfaces {
                fxp0.0;
            }
        }
    }
}`;

const SET_ZONES = `
set security zones security-zone trust description "Internal"
set security zones security-zone trust interfaces reth0.0 host-inbound-traffic system-services ping
set security zones security-zone trust interfaces reth0.100
set security zones functional-zone management interfaces fxp0.0`;

const IFACES = `
interfaces {
    reth0 {
        vlan-tagging;
        unit 0 {
            family inet {
                address 10.1.0.1/24;
            }
        }
        unit 100 {
            description "Voice";
            vlan-id 100;
            family inet {
                address 10.1.100.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 203.0.113.10/24;
            }
        }
    }
    ge-0/0/9 {
        disable;
        unit 0 {
            family inet {
                address 172.31.0.1/30;
            }
        }
    }
}`;

const STATICS = `
routing-options {
    static {
        route 0.0.0.0/0 next-hop 203.0.113.254;
        route 10.20.0.0/16 next-hop 10.1.0.9;
        route 10.30.0.0/16 next-hop 10.1.100.9;
        route 10.40.0.0/16 next-hop 192.0.2.9;
        route 172.16.0.0/12 next-hop st0.0;
        route 198.51.100.0/24 discard;
    }
}`;

const OPER_ROUTES = `
inet.0: 4 destinations, 5 routes (4 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 2w3d 04:12:33
                    >  to 203.0.113.254 via reth1.0
192.0.2.0/24       *[OSPF/10] 4d 09:12:00, metric 20
                    >  to 10.1.0.2 via reth0.0
                       to 10.1.0.3 via reth0.100
198.51.100.0/24    *[Static/5] 2w3d 04:12:33
                       Reject
`;

const OPER_SA = `
node0:
--------------------------------------------------------------------------
  ID: 500001 Virtual-system: root, VPN Name: half-open
  Local Gateway: 203.0.113.10, Remote Gateway: 198.51.100.77
  Local Identity: ipv4_subnet(any:0,[0..7]=0.0.0.0/0)
  Remote Identity: ipv4_subnet(any:0,[0..7]=10.9.0.0/16)
  Version: IKEv2
  Bind-interface: st0.0
    Direction: inbound, SPI: 0x0a2b3c4d, AUX-SPI: 0
      Hard lifetime: Expires in 2891 seconds
      Soft lifetime: Expires in 2276 seconds
      Mode: Tunnel(0 0), Type: dynamic, State: installed
      Protocol: ESP, Authentication: hmac-sha-256-128, Encryption: aes-256-cbc
    Direction: outbound, SPI: 0x1f2e3d4c, AUX-SPI: 0
      Hard lifetime: Expires in 2891 seconds
      Soft lifetime: Expires in 2301 seconds
      Mode: Tunnel(0 0), Type: dynamic, State: not installed
      Protocol: ESP, Authentication: hmac-sha-256-128, Encryption: aes-256-cbc
`;

const OPER_IKE = `
node0:
--------------------------------------------------------------------------
IKE peer 198.51.100.77, Index 6666666, Gateway Name: gw-branch
  Role: Initiator, State: UP
  Initiator cookie: 5d3f2a1b9c8e7f60, Responder cookie: a1b2c3d4e5f60718
  Exchange type: IKEv2, Authentication method: Pre-shared-keys
  Local: 203.0.113.10:500, Remote: 198.51.100.77:500
  Lifetime: Expires in 22391 seconds
  Peer ike-id: 198.51.100.77
  Algorithms:
   Authentication        : hmac_sha256_128
   Encryption            : aes256_cbc
   Pseudo random function: hmac_sha256
   Diffie-Hellman group  : DH-group-14
  IPSec security associations: 2 created, 0 deleted
  Phase 2 negotiations in progress: 0

IKE peer 192.0.2.200, Index 6666702, Gateway Name: gw-partner
  Role: Responder, State: DOWN
  Exchange type: Aggressive, Authentication method: Pre-shared-keys
  Local: 203.0.113.10:500, Remote: 192.0.2.200:500
  Algorithms:
   Authentication        : hmac_sha1_96
   Encryption            : 3des_cbc
   Diffie-Hellman group  : DH-group-2
  Phase 2 negotiations in progress: 1
`;

const OPER_IKE_SUMMARY = `
Index   State  Initiator cookie  Responder cookie  Mode           Remote Address
6666666 UP     5d3f2a1b9c8e7f60  a1b2c3d4e5f60718  IKEv2          198.51.100.77
6666702 DOWN   0011223344556677  8899aabbccddeeff  Aggressive     192.0.2.200
`;

const IPSEC_CFG = `
security {
    ike {
        gateway gw-branch { ike-policy p; address 198.51.100.77; external-interface reth1.0; version v2-only; }
        gateway gw-partner { ike-policy p; address 192.0.2.200; external-interface reth1.0; }
    }
    ipsec {
        vpn to-branch { bind-interface st0.0; ike { gateway gw-branch; } }
        vpn to-partner { bind-interface st0.1; ike { gateway gw-partner; } }
    }
    zones { security-zone vpn { interfaces { st0.0; } } }
}`;

/* ============================================== junos-config-report.html === */

describe("junos-config-report / flattener", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("reads brace form and set form onto the same paths", () => {
    const a = W.__flatten(BRACE_ZONES).map(r => r.p.join(" ")).sort();
    const b = W.__flatten(SET_ZONES).map(r => r.p.join(" ")).sort();
    eq(a, b, "the two config forms must flatten identically");
    includes(a.join("\n"), "security zones security-zone trust interfaces reth0.100");
  });

  it("keeps a quoted description as one token", () => {
    const rec = W.__flatten(`system { host-name "edge srx 01"; }`)[0];
    eq(rec.p, ["system", "host-name", "edge srx 01"]);
  });

  it("joins a bracket list that runs onto the next line", () => {
    const flat = W.__flatten([
      "set security policies from-zone a to-zone b policy p match application [",
      "    junos-http",
      "    junos-https ]"
    ].join("\n"));
    eq(flat.length, 1);
    eq(flat[0].p.slice(-2), ["junos-http", "junos-https"]);
  });

  it("carries an inactive: marker down the subtree", () => {
    const flat = W.__flatten(`security { policies { inactive: from-zone a to-zone b { policy p { then { permit; } } } } }`);
    ok(flat.length > 0, "expected statements");
    ok(flat.every(r => r.inactive), "every statement under an inactive block is inactive");
  });

  it("tags statements under groups so they are never matched as applied config", () => {
    const cfg = `groups { node0 { security { zones { security-zone ghost { interfaces { ge-0/0/0.0; } } } } } }`;
    const flat = W.__flatten(cfg);
    ok(flat.every(r => r.grp === "node0"), "expected every record tagged with its group");
    eq(W.__parseZones(cfg).length, 0, "a group template must not produce a zone");
  });

  it("skips prompts, node banners and comment lines", () => {
    const flat = W.__flatten([
      "{master:node0}",
      "user@srx> show configuration",
      "## Last commit: 2024-01-01",
      "node0:",
      "system { host-name srx; }"
    ].join("\n"));
    eq(flat.map(r => r.p.join(" ")), ["system host-name srx"]);
    eq(flat[0].node, "node0");
  });

  it("survives garbage without throwing", () => {
    eq(W.__flatten("").length, 0);
    eq(W.__flatten("}}}}\n];;;\nnot a config at all").length, 0);
    eq(W.__parseConfig("nothing to see here").zones.length, 0);
  });
});

describe("junos-config-report / addressing", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("masks IPv4 host bits off to the network", () => {
    eq(W.__network("10.1.0.37/24").cidr, "10.1.0.0/24");
    eq(W.__network("203.0.113.10/31").cidr, "203.0.113.10/31");
    eq(W.__network("10.255.255.1/32").cidr, "10.255.255.1/32");
  });

  it("masks IPv6 and re-compresses the result", () => {
    eq(W.__network("2001:db8:1:2:3:4:5:6/48").cidr, "2001:db8:1::/48");
    eq(W.__network("fe80::1/10").cidr, "fe80::/10");
    eq(W.__network("::ffff:10.0.0.1/128").cidr, "::ffff:a00:1/128");
  });

  it("returns null rather than a guess for anything malformed", () => {
    eq(W.__network("10.1.0.1"), null);
    eq(W.__network("999.1.1.1/24"), null);
    eq(W.__network("not-an-address/24"), null);
    eq(W.__network(""), null);
  });
});

describe("junos-config-report / config-derived routes", () => {
  const t = load("junos-config-report.html");
  const m = t.window.__parseConfig(IFACES + STATICS + BRACE_ZONES);

  const byPrefix = {};
  m.legs.forEach(l => { byPrefix[l.prefix] = l; });

  it("derives a connected route per interface address", () => {
    const direct = m.routes.filter(r => r.protocol === "Direct").map(r => r.prefix).sort();
    eq(direct, ["10.1.0.0/24", "10.1.100.0/24", "172.31.0.0/30", "203.0.113.0/24"]);
  });

  it("resolves a static next-hop to the connected interface it lands on", () => {
    eq(byPrefix["0.0.0.0/0"].iface, "reth1.0");
    eq(byPrefix["10.20.0.0/16"].iface, "reth0.0");
    eq(byPrefix["10.30.0.0/16"].iface, "reth0.100", "longest match must pick the .100 unit");
  });

  it("takes an interface-form next-hop directly", () => {
    eq(byPrefix["172.16.0.0/12"].iface, "st0.0");
    eq(byPrefix["172.16.0.0/12"].nh, "");
  });

  it("reports an off-subnet next-hop as unresolved instead of guessing", () => {
    eq(byPrefix["10.40.0.0/16"].iface, "");
    eq(byPrefix["10.40.0.0/16"].kind, "unresolved");
    eq(byPrefix["10.40.0.0/16"].nh, "192.0.2.9");
    eq(m.unresolvedNh, ["192.0.2.9"]);
  });

  it("gives discard routes no egress interface and therefore no zone", () => {
    eq(byPrefix["198.51.100.0/24"].kind, "discard");
    eq(byPrefix["198.51.100.0/24"].zone, "");
  });

  it("marks a route out of a disabled interface inactive", () => {
    const r = m.routes.filter(x => x.prefix === "172.31.0.0/30")[0];
    eq(r.active, false, "ge-0/0/9 is disabled, so its connected route is not active");
  });

  it("joins routes to zones through the egress interface", () => {
    eq(byPrefix["0.0.0.0/0"].zone, "");            // reth1.0 is in no zone here
    eq(byPrefix["10.20.0.0/16"].zone, "trust");
    ok(byPrefix["0.0.0.0/0"].unzoned, "an egress interface with no zone must be flagged");
  });
});

describe("junos-config-report / routing instances", () => {
  const t = load("junos-config-report.html");
  const m = t.window.__parseConfig(`
interfaces { reth2 { unit 0 { family inet { address 198.51.100.2/30; } } } }
routing-instances {
    ISP-B {
        instance-type virtual-router;
        interface reth2.0;
        routing-options { static { route 0.0.0.0/0 next-hop 198.51.100.1; } }
    }
}
security { zones { security-zone edge { interfaces { reth2.0; } } } }`);

  it("puts instance routes in the instance table", () => {
    eq(m.tables.sort(), ["ISP-B.inet.0"]);
  });
  it("resolves an instance next-hop against that instance's interfaces", () => {
    const leg = m.legs.filter(l => l.prefix === "0.0.0.0/0")[0];
    eq(leg.iface, "reth2.0");
    eq(leg.zone, "edge");
    eq(leg.table, "ISP-B.inet.0");
  });
  it("records the instance on the interface", () => {
    eq(m.ifx.units["reth2.0"].instance, "ISP-B");
  });
});

describe("junos-config-report / zones", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("reads interfaces from either config form", () => {
    for(const cfg of [BRACE_ZONES, SET_ZONES]){
      const z = W.__parseZones(cfg);
      eq(z.length, 2);
      eq(z[0].name, "trust");
      eq(z[0].interfaces, ["reth0.0", "reth0.100"], "host-inbound-traffic must not become an interface");
      eq(z[0].desc, "Internal");
      eq(z[1].kind, "functional");
    }
  });

  it("flags a logical interface claimed by two zones", () => {
    const z = W.__parseZones(`
set security zones security-zone a interfaces reth0.0
set security zones security-zone b interfaces reth0.0`);
    eq(z[0].dupes, ["reth0.0"]);
    eq(z[1].dupes, ["reth0.0"]);
  });

  it("flags a zone bound to an interface the config never defines", () => {
    const m = W.__parseConfig(IFACES + `security { zones { security-zone trust { interfaces { reth9.0; } } } }`);
    eq(m.zones[0].notConfigured, ["reth9.0"]);
    ok(m.zones[0].notes.some(n => n.level === "bad" && /not configured/.test(n.text)));
  });
});

describe("junos-config-report / policies", () => {
  const t = load("junos-config-report.html");
  const W = t.window;
  const CFG = `
security {
    address-book {
        global {
            address web 192.0.2.10/32;
            address-set inner { address web; address 10.0.0.0/8; }
        }
    }
    zones { security-zone trust { interfaces { reth0.0; } } security-zone untrust { interfaces { reth1.0; } } }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match { source-address inner; destination-address any; application [ junos-http junos-https ]; }
                then { permit; log { session-close; } }
            }
            policy catch-all {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
            policy never-reached {
                match { source-address inner; destination-address ghost-name; application any; }
                then { deny; }
            }
        }
        global { policy fallback { match { source-address any; destination-address any; application any; } then { deny; } } }
    }
}`;
  const m = W.__parseConfig(CFG);

  it("reads match and then off either form", () => {
    const p = m.policies[0];
    eq(p.from, "trust");
    eq(p.to, "untrust");
    eq(p.name, "allow-web");
    eq(p.src, ["inner"]);
    eq(p.app, ["junos-http", "junos-https"]);
    eq(p.action, "permit");
    eq(p.log, ["session-close"]);
  });

  it("numbers policies within their zone pair", () => {
    eq(m.policies.filter(p => !p.global).map(p => p.seq), [1, 2, 3]);
  });

  it("reads a global policy", () => {
    const g = m.policies.filter(p => p.global)[0];
    eq(g.name, "fallback");
    eq(g.action, "deny");
  });

  it("marks a policy shadowed by an earlier catch-all", () => {
    eq(m.policies[2].shadowedBy, "catch-all");
    ok(m.policies[2].notes.some(n => /Unreachable/.test(n.text)));
    ok(!m.policies[0].shadowedBy, "a policy before the catch-all is still reachable");
  });

  it("flags a policy with no then action", () => {
    const m2 = W.__parseConfig(`security { policies { from-zone a to-zone b { policy p { match { source-address any; } } } } }`);
    ok(m2.policies[0].notes.some(n => n.level === "bad" && /no then action/i.test(n.text)));
  });

  it("resolves address sets recursively and flags an undefined name", () => {
    const html = renderPolicies(load("junos-config-report.html"), CFG);
    includes(html, "inner");
    includes(html, "192.0.2.10/32", "a set member should resolve to its prefix");
    includes(html, "not in the address book", "ghost-name is undefined and must say so");
  });
});

function renderPolicies(t, cfg){
  t.$("raw").value = cfg;
  t.$("parseBtn").click();
  t.$("viewPolicies").click();
  return t.$("table").innerHTML;
}

describe("junos-config-report / address book", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("reads the global book, nested sets and range addresses", () => {
    const b = W.__parseAddressBook(`
set security address-book global address web 192.0.2.10/32
set security address-book global address pool range-address 10.0.0.1 to 10.0.0.9
set security address-book global address-set inner address web
set security address-book global address-set outer address-set inner`);
    eq(b.books.global.addresses.web, "192.0.2.10/32");
    includes(b.books.global.addresses.pool, "10.0.0.1");
    includes(b.books.global.addresses.pool, "10.0.0.9");
    eq(b.books.global.sets.inner, ["web"]);
    eq(b.books.global.sets.outer, ["inner"]);
  });

  it("reads a zone-scoped book and records the zone it serves", () => {
    const b = W.__parseAddressBook(`
security { zones { security-zone trust { address-book { address local 10.0.0.0/8; } } } }`);
    eq(b.books["zone trust"].addresses.local, "10.0.0.0/8");
    eq(b.books["zone trust"].zones, ["trust"]);
  });

  it("attaches a named book to its zones", () => {
    const b = W.__parseAddressBook(`
set security address-book branch address lan 172.16.0.0/12
set security address-book branch attach zone vpn`);
    eq(b.books.branch.zones, ["vpn"]);
  });
});

describe("junos-config-report / ipsec", () => {
  const t = load("junos-config-report.html");
  const W = t.window;
  const CFG = `
security {
    ike {
        proposal weak { dh-group group2; authentication-algorithm sha1; encryption-algorithm 3des-cbc; }
        policy pol { mode aggressive; proposals weak; pre-shared-key ascii-text "$9$SUPERSECRETKEYMATERIAL"; }
        gateway gw { ike-policy pol; address 198.51.100.77; external-interface reth1.0; }
    }
    ipsec {
        proposal p2 { protocol esp; authentication-algorithm hmac-md5-96; encryption-algorithm 3des-cbc; }
        policy ipol { proposals p2; }
        vpn tunnel-a { bind-interface st0.0; ike { gateway gw; ipsec-policy ipol; } }
        vpn tunnel-b { bind-interface st0.1; ike { gateway missing-gw; } }
    }
    zones { security-zone vpn { interfaces { st0.0; } } }
}`;
  const m = W.__parseConfig(CFG);

  it("joins vpn to gateway to policy to proposal", () => {
    const a = m.vpns[0];
    eq(a.name, "tunnel-a");
    eq(a.vpn.bind, "st0.0");
    eq(a.gw.addresses, ["198.51.100.77"]);
    eq(a.ikePol.mode, "aggressive");
    eq(a.ikeProps[0].enc, "3des-cbc");
    eq(a.ipsProps[0].auth, "hmac-md5-96");
  });

  it("flags a reference to a gateway that is not defined", () => {
    ok(m.vpns[1].missingGw);
    ok(m.vpns[1].notes.some(n => n.level === "bad" && /not defined/.test(n.text)));
  });

  it("flags a bind-interface that is in no zone", () => {
    ok(m.vpns[1].notes.some(n => n.level === "bad" && /st0\.1 is not bound to any security zone/.test(n.text)));
    ok(!m.vpns[0].notes.some(n => /not bound to any security zone/.test(n.text)));
  });

  it("calls out weak crypto, aggressive mode and missing PFS", () => {
    const text = m.vpns[0].notes.map(n => n.text).join(" ");
    includes(text, "Deprecated encryption");
    includes(text, "Legacy authentication");
    includes(text, "Weak Diffie-Hellman");
    includes(text, "aggressive mode");
    includes(text, "perfect forward secrecy");
  });

  it("never captures or renders pre-shared key material", () => {
    ok(m.vpns[0].ikePol.hasPsk, "the presence of a key should still be reported");
    excludes(JSON.stringify(m), "SUPERSECRETKEYMATERIAL", "key material must never reach the model");
    const t2 = load("junos-config-report.html");
    t2.$("raw").value = CFG;
    t2.$("parseBtn").click();
    t2.$("viewVpn").click();
    excludes(t2.doc.body.innerHTML, "SUPERSECRETKEYMATERIAL", "key material must never reach the DOM");
    includes(t2.$("cards").textContent, "pre-shared key is configured");
  });
});

describe("junos-config-report / operational output alongside the config", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("still parses show route output", () => {
    const r = W.__parseRoutes(OPER_ROUTES);
    eq(r.tables, ["inet.0"]);
    eq(r.routes.length, 3);
    eq(r.routes[1].paths.length, 2, "ECMP next-hops become two paths");
    eq(r.routes[2].paths[0].kind, "reject");
    ok(r.routes.every(x => x.src === "show route"));
  });

  it("does not treat 'not installed' as installed", () => {
    const sas = W.__parseSAs(OPER_SA);
    eq(sas.length, 1);
    eq(sas[0].status, "partial");
    eq(sas[0].outbound.state, "not installed");
    eq(sas[0].remoteId, "10.9.0.0/16", "the proxy ID should come out of the ipv4_subnet wrapper");
  });

  it("prefers the live RIB but keeps config routes the paste never covered", () => {
    const m = W.__parseConfig(IFACES + STATICS + BRACE_ZONES + "\n" + OPER_ROUTES);
    const byPrefix = {};
    m.routes.forEach(r => { byPrefix[r.prefix] = r; });
    eq(byPrefix["0.0.0.0/0"].src, "show route", "a prefix in both should come from the live RIB");
    eq(byPrefix["10.20.0.0/16"].src, "config", "a config-only prefix should survive the merge");
    eq(m.supersededRoutes, 2);
    ok(m.missingStatics.map(r => r.prefix).indexOf("10.20.0.0/16") !== -1);
  });

  it("attaches a live SA to the VPN card of the same name", () => {
    const m = W.__parseConfig(
      `security { ipsec { vpn half-open { bind-interface st0.0; } } }` + "\n" + OPER_SA);
    eq(m.vpns[0].sa.status, "partial");
    eq(m.orphanSAs.length, 0);
  });

  it("keeps an SA with no matching config as its own card", () => {
    const m = W.__parseConfig(OPER_SA);
    eq(m.vpns.length, 0);
    eq(m.orphanSAs.length, 1);
    eq(m.orphanSAs[0].name, "half-open");
  });
});

describe("junos-config-report / weak algorithm naming", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  // The config and the operational output name the same algorithm differently, and
  // the same rule has to cover both spellings.
  it("judges encryption the same in either spelling", () => {
    const m = W.__parseConfig(`security { ipsec { proposal p { encryption-algorithm 3des_cbc; } policy pol { proposals p; } vpn v { ike { ipsec-policy pol; } } } }`);
    ok(m.vpns[0].notes.some(n => /Deprecated encryption/.test(n.text)), "3des_cbc must read as weak");
    const m2 = W.__parseConfig(`security { ipsec { proposal p { encryption-algorithm aes-256-cbc; } policy pol { proposals p; } vpn v { ike { ipsec-policy pol; } } } }`);
    ok(!m2.vpns[0].notes.some(n => /Deprecated encryption/.test(n.text)), "aes-256-cbc must not");
  });

  it("does not mistake sha-256 for sha1", () => {
    const ikes = W.__parseIKE(OPER_IKE);
    ok(!ikes[0].notes.some(n => /deprecated algorithms/.test(n.text)), "hmac_sha256_128 / aes256_cbc / DH-group-14 are current");
    ok(ikes[1].notes.some(n => /deprecated algorithms/.test(n.text)), "hmac_sha1_96 / 3des_cbc / DH-group-2 are not");
  });

  it("reads the Diffie-Hellman group as a number, not a prefix", () => {
    const ikes = W.__parseIKE(OPER_IKE);
    eq(ikes[0].dh, "DH-group-14");
    ok(ikes[1].notes.some(n => /DH-group-2/.test(n.text)));
  });
});

describe("junos-config-report / ike security-associations", () => {
  const t = load("junos-config-report.html");
  const W = t.window;

  it("reads the detail form", () => {
    const k = W.__parseIKE(OPER_IKE);
    eq(k.length, 2);
    eq(k[0].gwName, "gw-branch");
    eq(k[0].peer, "198.51.100.77");
    eq(k[0].role, "Initiator");
    eq(k[0].state, "UP");
    eq(k[0].status, "up");
    eq(k[0].exchange, "IKEv2");
    eq(k[0].lifetime, 22391);
    eq(k[0].local, "203.0.113.10", "the port must be split off the local address");
    eq(k[0].localPort, "500");
    eq(k[0].created, "2");
    eq(k[1].status, "down");
  });

  it("does not read 'Authentication method' as the authentication algorithm", () => {
    const k = W.__parseIKE(OPER_IKE);
    eq(k[0].auth, "hmac_sha256_128");
    eq(k[0].authMethod, "Pre-shared-keys");
  });

  it("reads the summary form too", () => {
    const k = W.__parseIKE(OPER_IKE_SUMMARY);
    eq(k.length, 2);
    eq(k[0].index, "6666666");
    eq(k[0].status, "up");
    eq(k[0].peer, "198.51.100.77");
    eq(k[0].exchange, "IKEv2");
    ok(k[0].summaryOnly);
    eq(k[1].status, "down");
  });

  it("flags phase 2 negotiations still in progress", () => {
    const k = W.__parseIKE(OPER_IKE);
    ok(k[1].notes.some(n => /still in progress/.test(n.text)));
  });

  it("survives garbage and empty input", () => {
    eq(W.__parseIKE(""), []);
    eq(W.__parseIKE("nothing here at all"), []);
  });

  it("matches an IKE SA to its gateway by name", () => {
    const m = W.__parseConfig(IPSEC_CFG, { ike: OPER_IKE });
    eq(m.ikes.length, 2);
    eq(m.orphanIKE.length, 0);
    eq(m.vpns[0].name, "to-branch");
    eq(m.vpns[0].ikes.length, 1);
    eq(m.vpns[0].ikes[0].gwName, "gw-branch");
    eq(m.vpns[1].ikes[0].gwName, "gw-partner");
  });

  it("falls back to the peer address when the output carries no gateway name", () => {
    const noName = OPER_IKE.replace(/, Gateway Name: \S+/g, "");
    const m = W.__parseConfig(IPSEC_CFG, { ike: noName });
    eq(m.orphanIKE.length, 0);
    eq(m.vpns[0].ikes[0].peer, "198.51.100.77");
  });

  it("keeps an IKE SA that matches no gateway as its own card", () => {
    const m = W.__parseConfig(IPSEC_CFG, { ike: OPER_IKE.replace(/gw-branch/, "gw-nowhere").replace(/198\.51\.100\.77/g, "203.0.113.99") });
    eq(m.orphanIKE.length, 1);
    eq(m.orphanIKE[0].gwName, "gw-nowhere");
    eq(m.vpns[0].ikes.length, 0);
  });

  it("reports phase 1 up with no phase 2 behind it", () => {
    const m = W.__parseConfig(IPSEC_CFG, { ike: OPER_IKE });
    ok(m.vpns[0].liveNotes.some(n => /Phase 1 is up but no IPsec SA/.test(n.text)));
  });

  it("reports a phase 1 that negotiated a different IKE version than configured", () => {
    const m = W.__parseConfig(IPSEC_CFG, { ike: OPER_IKE.replace("Exchange type: IKEv2", "Exchange type: Main") });
    ok(m.vpns[0].liveNotes.some(n => /configured v2-only but phase 1 negotiated Main/.test(n.text)));
  });

  it("says nothing about the version when the gateway does not pin one", () => {
    const m = W.__parseConfig(IPSEC_CFG, { ike: OPER_IKE });
    ok(!m.vpns[1].liveNotes.some(n => /negotiated/.test(n.text)), "gw-partner pins no version");
  });
});

describe("junos-config-report / optional panes", () => {
  it("parses the panes and the config box as one input", () => {
    const t = load("junos-config-report.html");
    const W = t.window;
    const split  = W.__parseConfig(IFACES + STATICS + BRACE_ZONES, { routes: OPER_ROUTES, sas: OPER_SA, ike: OPER_IKE });
    const merged = W.__parseConfig(IFACES + STATICS + BRACE_ZONES + OPER_ROUTES + OPER_SA + OPER_IKE);
    eq(split.routes.length, merged.routes.length, "pane and single-box input must agree");
    eq(split.sas.length, merged.sas.length);
    eq(split.ikes.length, merged.ikes.length);
    eq(split.opRouteCount, merged.opRouteCount);
  });

  it("reports per pane what that pane alone yielded", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value       = BRACE_ZONES;
    t.$("rawRoutes").value = OPER_ROUTES;
    t.$("rawIKE").value    = OPER_IKE;
    t.$("parseBtn").click();
    includes(t.text("routeState"), "3 routes");
    eq(t.text("saState"), "optional");
    includes(t.text("ikeState"), "2 SAs");
    includes(t.text("optState"), "IKE SA");
  });

  it("says so when a pane holds something it cannot read", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value    = BRACE_ZONES;
    t.$("rawIKE").value = "this is not ike output";
    t.$("parseBtn").click();
    eq(t.text("ikeState"), "nothing recognised");
  });

  it("opens the optional section and fills every pane from the sample", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    eq(t.errors, []);
    ok(t.$("opt").classList.contains("on"), "the sample should reveal the panes it used");
    eq(t.$("optToggle").getAttribute("aria-expanded"), "true");
    ok(t.$("rawRoutes").value.length > 0);
    ok(t.$("rawSAs").value.length > 0);
    ok(t.$("rawIKE").value.length > 0);
    includes(t.text("srcline"), "ike security-associations");
  });

  it("toggles the optional section", () => {
    const t = load("junos-config-report.html");
    t.$("optToggle").click();
    ok(t.$("opt").classList.contains("on"));
    t.$("optToggle").click();
    ok(!t.$("opt").classList.contains("on"));
  });

  it("clears every pane", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("clearBtn").click();
    eq(t.$("rawRoutes").value, "");
    eq(t.$("rawSAs").value, "");
    eq(t.$("rawIKE").value, "");
    eq(t.text("ikeState"), "optional");
    eq(t.text("optState"), "");
    ok(!t.$("opt").classList.contains("on"));
  });

  it("builds a report from the panes alone, with no configuration at all", () => {
    const t = load("junos-config-report.html");
    t.$("rawIKE").value = OPER_IKE;
    t.$("parseBtn").click();
    ok(!t.$("msg").classList.contains("on"), "live state on its own is still a report");
    t.$("viewVpn").click();
    includes(t.text("cards"), "gw-branch");
    includes(t.text("cards"), "phase 1 only");
  });
});

describe("junos-config-report / operational output already in the config paste", () => {
  // What an engineer actually pastes: the config and every show command, one box.
  const WHOLE = [
    IFACES, STATICS, BRACE_ZONES,
    "", "user@srx> show route", "", OPER_ROUTES,
    "", "user@srx> show security ipsec security-associations detail", "", OPER_SA,
    "", "user@srx> show security ike security-associations detail", "", OPER_IKE
  ].join("\n");

  const SPLIT_CFG = IFACES + STATICS + BRACE_ZONES;
  const SPLIT_EXTRA = { routes: OPER_ROUTES, sas: OPER_SA, ike: OPER_IKE };

  function shape(m){
    return { routes: m.routes.length, op: m.opRouteCount, sas: m.sas.length,
             ikes: m.ikes.length, tables: m.tables.slice().sort() };
  }

  it("reads the same model however the input is divided up", () => {
    const W = load("junos-config-report.html").window;
    const split = shape(W.__parseConfig(SPLIT_CFG, SPLIT_EXTRA));
    const whole = shape(W.__parseConfig(WHOLE));
    const both  = shape(W.__parseConfig(WHOLE, SPLIT_EXTRA));
    eq(whole, split, "one box and separate panes must agree");
    eq(both, split, "supplying it twice must not double anything");
  });

  it("counts a capture once when it is supplied twice", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig(WHOLE, SPLIT_EXTRA);
    eq(m.opDuplicates.routes, 3);
    eq(m.opDuplicates.sas, 1);
    eq(m.opDuplicates.ike, 2);
    ok(m.routes.length > 0);
  });

  it("keeps captures that only look alike", () => {
    const W = load("junos-config-report.html").window;
    const other = `
inet.3: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

10.9.9.9/32        *[RSVP/7] 1d 00:00:01
                    >  via st0.0
`;
    const m = W.__parseConfig(SPLIT_CFG + OPER_ROUTES, { routes: other });
    eq(m.opDuplicates.routes, 0, "a different table is not a duplicate");
    ok(m.tables.indexOf("inet.3") !== -1);
    ok(m.tables.indexOf("inet.0") !== -1);
  });

  it("tells each pane the configuration paste already covers it", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = WHOLE;
    t.$("parseBtn").click();
    includes(t.text("routeState"), "already in the configuration");
    includes(t.text("saState"), "already in the configuration");
    includes(t.text("ikeState"), "already in the configuration");
    includes(t.text("routeState"), "3 routes");
    eq(t.doc.getElementById("routeState").className, "state found");
  });

  it("says so on the collapsed header, so the section need not be opened", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = WHOLE;
    t.$("parseBtn").click();
    ok(!t.$("opt").classList.contains("on"), "nothing was pasted into a pane, so it stays shut");
    includes(t.text("optState"), "already in the configuration paste");
    includes(t.text("optState"), "IKE SA");
  });

  it("distinguishes panes from the config paste on the header", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = WHOLE;
    t.$("rawIKE").value = OPER_IKE;
    t.$("parseBtn").click();
    includes(t.text("optState"), "from the panes and the configuration paste");
  });

  it("reports the repeat as a finding rather than silently dropping it", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = WHOLE;
    t.$("rawRoutes").value = OPER_ROUTES;
    t.$("parseBtn").click();
    t.$("viewOverview").click();
    includes(t.text("ov"), "appears more than once in the input");
  });

  it("leaves the panes marked optional when the config carries no live output", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = SPLIT_CFG;
    t.$("parseBtn").click();
    eq(t.text("routeState"), "optional");
    eq(t.text("saState"), "optional");
    eq(t.text("ikeState"), "optional");
    eq(t.text("optState"), "");
  });
});

describe("junos-config-report / rekey bar", () => {
  const LIFE_CFG = `
security {
    ike {
        proposal ikep { encryption-algorithm aes-256-cbc; lifetime-seconds 28800; }
        policy pol { proposals ikep; }
        gateway gw { ike-policy pol; address 198.51.100.77; external-interface reth1.0; }
    }
    ipsec {
        proposal p2 { encryption-algorithm aes-256-cbc; lifetime-seconds 3600; }
        policy ipol { proposals p2; perfect-forward-secrecy { keys group14; } }
        vpn half-open { bind-interface st0.0; ike { gateway gw; ipsec-policy ipol; } }
    }
    zones { security-zone vpn { interfaces { st0.0; } } }
}`;

  function lanes(t){
    t.$("viewVpn").click();
    return [...t.doc.querySelectorAll("#cards .lane")].filter(l => l.querySelector(".bar")).map(l => ({
      dir: l.querySelector(".dir").textContent.trim(),
      width: l.querySelector(".bar span").getAttribute("style"),
      title: l.querySelector(".bar").getAttribute("title"),
      text: (l.querySelector(".life .t") || {}).textContent || ""
    }));
  }

  it("draws a lifetime bar on each half-tunnel", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = LIFE_CFG;
    t.$("rawSAs").value = OPER_SA;
    t.$("parseBtn").click();
    const l = lanes(t);
    const ipsec = l.filter(x => /bound$/.test(x.dir));
    eq(ipsec.length, 2, "one bar per direction");
    includes(ipsec[0].text, "hard ");
    includes(ipsec[0].text, "soft ");
  });

  it("scales the bar against the lifetime the VPN is configured to rekey at", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = LIFE_CFG;
    t.$("rawSAs").value = OPER_SA;
    t.$("rawIKE").value = OPER_IKE.replace(/Gateway Name: gw-branch/, "Gateway Name: gw");
    t.$("parseBtn").click();
    const l = lanes(t);

    // 2891s remaining of a configured 3600s hard lifetime.
    const out = l.filter(x => /outbound/.test(x.dir))[0];
    eq(out.width, "width:80%");
    includes(out.title, "configured to rekey at");
    includes(out.title, "1h 00m");

    // 22391s remaining of a configured 28800s phase 1 lifetime.
    const ike = l.filter(x => /^IKE/.test(x.dir))[0];
    eq(ike.width, "width:78%");
    includes(ike.title, "8h 00m");
  });

  it("falls back to the longest lifetime in the capture when none is configured", () => {
    const t = load("junos-config-report.html");
    t.$("rawSAs").value = OPER_SA;          // no configuration at all
    t.$("parseBtn").click();
    const out = lanes(t).filter(x => /outbound/.test(x.dir))[0];
    eq(out.width, "width:100%", "the longest in the capture fills the bar");
    includes(out.title, "scaled to the longest lifetime in this capture");
  });

  it("does not draw a bar for a phase 1 that reports no lifetime", () => {
    const t = load("junos-config-report.html");
    t.$("rawIKE").value = OPER_IKE;
    t.$("parseBtn").click();
    const withBar = lanes(t).filter(x => /^IKE/.test(x.dir));
    eq(withBar.length, 1, "only the UP peer reports a lifetime in this fixture");
  });
});

describe("junos-config-report / DOM", () => {
  const t = load("junos-config-report.html");
  const { $, doc } = t;

  it("loads the sample with no page errors", () => {
    $("sampleBtn").click();
    eq(t.errors, []);
    ok(!$("msg").classList.contains("on"), "the sample must not raise a failure message");
    includes(t.text("inputState"), "zones");
  });

  it("summarises what it read", () => {
    includes(t.text("stats"), "Logical interfaces");
    includes(t.text("srcline"), "config statement");
    includes(t.text("srcline"), "show route");
    includes(t.text("srcline"), "edge-srx-01");
  });

  it("opens on the overview and links through to a view", () => {
    ok($("ov").classList.contains("on"));
    includes(t.text("ov"), "Unresolved next-hops");
    includes(t.text("ov"), "does not fall inside any configured connected subnet");
    doc.querySelector('.ov-card[data-view="routes"]').dispatchEvent(new t.window.Event("click", { bubbles: true }));
    eq($("viewRoutes").getAttribute("aria-pressed"), "true");
  });

  it("renders every view", () => {
    $("viewIfaces").click();
    includes(t.text("table"), "reth0.100");
    ok($("tableWrap").classList.contains("on"));

    $("viewZones").click();
    includes(t.text("cards"), "ISP-B-EDGE");
    includes(t.text("cards"), "No interfaces bound");

    $("viewRoutes").click();
    includes(t.text("table"), "203.0.113.254");
    includes(t.text("table"), "show route");
    includes(t.text("table"), "config");

    $("viewDiagram").click();
    ok($("diagram").querySelector("svg"), "the diagram must render an inline svg");
    includes(t.text("dgmCaption"), "zone");

    $("viewPolicies").click();
    includes(t.text("table"), "allow-web");
    includes(t.text("table"), "permit");

    $("viewVpn").click();
    includes(t.text("cards"), "to-branch");
    includes(t.text("cards"), "st0.0");
    includes(t.text("cards"), "Live state");
    includes(t.text("cards"), "IKE Initiator", "phase 1 belongs on the card next to phase 2");
    includes(t.text("cards"), "ike up");
    includes(t.text("cards"), "ike down", "the partner tunnel is down at phase 1");
  });

  it("leads the VPN notes with live state, not configuration advice", () => {
    $("viewVpn").click();
    const partner = [...doc.querySelectorAll("#cards .card")].filter(c => /to-partner/.test(c.textContent))[0];
    const notes = [...partner.querySelectorAll(".note")].map(n => n.textContent);
    ok(/Phase 1 is DOWN/.test(notes[0]), `expected the down phase 1 first, got: ${notes[0]}`);
  });

  it("draws one interface box per bound interface in the diagram", () => {
    $("viewDiagram").click();
    const items = t.window.__diagramItems();
    const trust = items.filter(i => i.name === "trust")[0];
    eq(trust.ifaces.map(f => f.name), ["reth0.0", "reth0.100"]);
    ok(items.some(i => i.unzoned), "st0.1 and lo0.0 belong to no zone, so an unzoned group is expected");
  });

  it("filters across views", () => {
    $("viewRoutes").click();
    $("filter").value = "st0.0";
    $("filter").dispatchEvent(new t.window.Event("input"));
    includes(t.text("table"), "172.16.8.0/22");
    excludes(t.text("table"), "203.0.113.254");
    $("filter").value = "";
    $("filter").dispatchEvent(new t.window.Event("input"));
    includes(t.text("table"), "203.0.113.254");
  });

  it("narrows to problems only", () => {
    $("viewZones").click();
    const all = doc.querySelectorAll("#cards .card").length;
    $("problemsOnly").checked = true;
    $("problemsOnly").dispatchEvent(new t.window.Event("change"));
    const some = doc.querySelectorAll("#cards .card").length;
    ok(some > 0 && some < all, `expected fewer than ${all} zone cards, got ${some}`);
    $("problemsOnly").checked = false;
    $("problemsOnly").dispatchEvent(new t.window.Event("change"));
  });

  it("exports every view without throwing", () => {
    for(const v of ["viewOverview","viewIfaces","viewZones","viewRoutes","viewDiagram","viewPolicies","viewVpn"]){
      $(v).click();
      $("csvBtn").click();
      $("mdBtn").click();
    }
    $("viewDiagram").click();
    $("svgBtn").click();
    eq(t.errors, []);
  });

  it("names downloads after the host and keeps the name filesystem-safe", () => {
    const t2 = load("junos-config-report.html");
    t2.$("raw").value = `system { host-name "edge srx/01"; }\ninterfaces { reth0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`;
    t2.$("parseBtn").click();
    const names = [];
    t2.window.HTMLAnchorElement.prototype.click = function(){ names.push(this.download); };
    t2.$("viewRoutes").click(); t2.$("csvBtn").click();
    t2.$("viewDiagram").click(); t2.$("svgBtn").click();
    eq(names, ["edge-srx-01-routes-by-zone.csv", "edge-srx-01-zone-diagram.svg"]);
  });

  it("clears back to an empty page", () => {
    $("clearBtn").click();
    eq($("raw").value, "");
    eq(t.text("inputState"), "not parsed");
    ok(!$("summary").classList.contains("on"));
    ok(!$("toolbar").classList.contains("on"));
    eq(t.text("cards"), "");
    eq(t.errors, []);
  });
});

describe("junos-config-report / failure messages", () => {
  it("says what it saw when the paste is not a config", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = "the quick brown fox\njumped over the lazy dog";
    t.$("parseBtn").click();
    ok(t.$("msg").classList.contains("on"));
    includes(t.text("msgTitle"), "Nothing recognised");
    includes(t.text("msgBody"), "2 non-blank lines");
    includes(t.text("msgBody"), "the quick brown fox");
  });

  it("names the top-level hierarchies it did find", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = `snmp { community public { authorization read-only; } }`;
    t.$("parseBtn").click();
    includes(t.text("msgBody"), "snmp");
    includes(t.text("msgBody"), "routing-options");
  });

  it("recognises a subtree pasted without its path and says how to fix it", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = `
from-zone trust to-zone untrust {
    policy allow-web {
        match { source-address any; destination-address any; application any; }
        then { permit; }
    }
}`;
    t.$("parseBtn").click();
    ok(t.$("msg").classList.contains("on"));
    includes(t.text("msgBody"), "display set");
    includes(t.text("msgBody"), "security policies");
  });

  it("prompts for the config when only show route output is pasted", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = OPER_ROUTES;
    t.$("parseBtn").click();
    ok(!t.$("msg").classList.contains("on"), "routes alone are still a usable report");
    t.$("viewRoutes").click();
    includes(t.text("table"), "203.0.113.254");
  });
});

/* ------------------------------------------------------------------ report -- */

if(failures.length){
  console.log("");
  failures.forEach(f => {
    console.log(`FAIL  ${f.group} :: ${f.name}`);
    console.log(`      ${f.err.message.split("\n").join("\n      ")}`);
  });
  console.log(`\n${passed} passed, ${failures.length} failed\n`);
  process.exit(1);
}
console.log(`\n${passed} passed\n`);
