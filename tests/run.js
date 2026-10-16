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
// FileReader is asynchronous, so a few tests are too. They run after the synchronous
// ones and the report waits for them.
const pending = [];
function itAsync(name, fn){
  const g = group;
  pending.push(Promise.resolve().then(fn).then(() => { passed++; }, err => { failures.push({ group:g, name, err }); }));
}
function until(cond, ms){
  const end = Date.now() + (ms || 2000);
  return new Promise((resolve, reject) => {
    (function poll(){
      if(cond()) return resolve();
      if(Date.now() > end) return reject(new Error("timed out waiting"));
      setTimeout(poll, 10);
    })();
  });
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
    // show configuration prints no node banners, so one here came from a capture
    // pasted alongside and must not tag the configuration.
    eq(flat[0].node, "");
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
    const m = W.__parseConfig(IPSEC_CFG + "\n" + OPER_IKE);
    eq(m.ikes.length, 2);
    eq(m.orphanIKE.length, 0);
    eq(m.vpns[0].name, "to-branch");
    eq(m.vpns[0].ikes.length, 1);
    eq(m.vpns[0].ikes[0].gwName, "gw-branch");
    eq(m.vpns[1].ikes[0].gwName, "gw-partner");
  });

  it("falls back to the peer address when the output carries no gateway name", () => {
    const noName = OPER_IKE.replace(/, Gateway Name: \S+/g, "");
    const m = W.__parseConfig(IPSEC_CFG + "\n" + noName);
    eq(m.orphanIKE.length, 0);
    eq(m.vpns[0].ikes[0].peer, "198.51.100.77");
  });

  it("keeps an IKE SA that matches no gateway as its own card", () => {
    const m = W.__parseConfig(IPSEC_CFG + "\n" + OPER_IKE.replace(/gw-branch/, "gw-nowhere").replace(/198\.51\.100\.77/g, "203.0.113.99"));
    eq(m.orphanIKE.length, 1);
    eq(m.orphanIKE[0].gwName, "gw-nowhere");
    eq(m.vpns[0].ikes.length, 0);
  });

  it("reports phase 1 up with no phase 2 behind it", () => {
    const m = W.__parseConfig(IPSEC_CFG + "\n" + OPER_IKE);
    ok(m.vpns[0].liveNotes.some(n => /Phase 1 is up but no IPsec SA/.test(n.text)));
  });

  it("reports a phase 1 that negotiated a different IKE version than configured", () => {
    const m = W.__parseConfig(IPSEC_CFG + "\n" + OPER_IKE.replace("Exchange type: IKEv2", "Exchange type: Main"));
    ok(m.vpns[0].liveNotes.some(n => /configured v2-only but phase 1 negotiated Main/.test(n.text)));
  });

  it("says nothing about the version when the gateway does not pin one", () => {
    const m = W.__parseConfig(IPSEC_CFG + "\n" + OPER_IKE);
    ok(!m.vpns[1].liveNotes.some(n => /negotiated/.test(n.text)), "gw-partner pins no version");
  });
});

describe("junos-config-report / one box", () => {
  // What an engineer actually pastes: the config and every show command, one box.
  const CFG = IFACES + STATICS + BRACE_ZONES;
  const WHOLE = [
    CFG,
    "", "user@srx> show route", "", OPER_ROUTES,
    "", "user@srx> show security ipsec security-associations detail", "", OPER_SA,
    "", "user@srx> show security ike security-associations detail", "", OPER_IKE
  ].join("\n");

  function shape(m){
    return { routes: m.routes.length, op: m.opRouteCount, sas: m.sas.length,
             ikes: m.ikes.length, tables: m.tables.slice().sort() };
  }
  function tick(t, id){
    const el = t.$(id);
    return { on: el.classList.contains("on"), mark: el.querySelector(".mark").textContent,
             found: el.querySelector(".found").textContent };
  }

  it("picks every capture out of the one box", () => {
    const m = load("junos-config-report.html").window.__parseConfig(WHOLE);
    eq(m.opRouteCount, 3);
    eq(m.sas.length, 1);
    eq(m.ikes.length, 2);
    ok(m.zones.length > 0 && m.ifx.order.length > 0, "and the configuration around them");
  });

  it("reads the same model whatever order the captures come in", () => {
    const W = load("junos-config-report.html").window;
    const shuffled = [OPER_IKE, CFG, OPER_SA, OPER_ROUTES].join("\n");
    eq(shape(W.__parseConfig(shuffled)), shape(W.__parseConfig(WHOLE)));
  });

  it("counts a capture once when it is pasted twice", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig(WHOLE + "\nuser@srx> show route\n" + OPER_ROUTES +
                              "\nuser@srx> show security ipsec security-associations detail\n" + OPER_SA +
                              "\nuser@srx> show security ike security-associations detail\n" + OPER_IKE);
    eq(shape(m), shape(W.__parseConfig(WHOLE)), "pasting it twice must not double anything");
    eq(m.opDuplicates.routes, 3);
    eq(m.opDuplicates.sas, 1);
    eq(m.opDuplicates.ike, 2);
  });

  it("does not let one command's node banner tag the next command's output", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("node0:\n" + OPER_IKE + "\nuser@srx> show route\n" + OPER_ROUTES);
    eq(m.ikes[0].node, "node0");
    ok(m.routes.filter(r => r.src !== "config").every(r => r.node === ""), "routes came after a prompt, not under node0");
  });

  // The configuration must come out the same whatever is pasted around it: captures
  // before it, after it, both, twice, with or without prompts, glued on with no prompt
  // of its own, and with stray characters that a flattener would read as structure.
  const STRAY = ["  AS path: 64512 {64513 64514", "  Local Identity: ipv4_subnet(any:0,[0..7]=10.1.0.0/24",
                 "  }; stray", "node0:", "------"].join("\n");
  const CAPS = { routes:["show route", OPER_ROUTES], sa:["show security ipsec security-associations detail", OPER_SA],
                 ike:["show security ike security-associations detail", OPER_IKE], stray:["show route extensive", STRAY] };

  it("reads the configuration the same whatever is pasted around it", () => {
    const W = load("junos-config-report.html").window;
    const flatOf = t => W.__parseConfig(t).flat.map(r => JSON.stringify([r.p.join(" "), r.inactive, r.node, r.grp]));
    const SETFORM = W.__flatten(CFG).map(r => "set " + r.p.join(" ")).join("\n");
    const fails = [];
    for(const [form, cfg] of [["brace", CFG], ["set", SETFORM]]){
      const want = flatOf(cfg);
      for(const prompt of [true, false]) for(const where of ["before", "after", "both", "glued"])
      for(const k of Object.keys(CAPS)) for(const twice of [false, true]){
        const one = (prompt ? "user@srx> " + CAPS[k][0] + "\n" : "") + CAPS[k][1];
        const cap = twice ? one + "\n" + one : one;
        const head = prompt && where !== "glued" ? "user@srx> show configuration\n" : "";
        const text = where === "before" ? cap + "\n" + head + cfg
                   : where === "after"  ? head + cfg + "\n" + cap
                   : where === "glued"  ? cap + "\n" + cfg
                   : cap + "\n" + head + cfg + "\n" + cap;
        const got = new Set(flatOf(text));
        const lost = want.filter(x => !got.has(x));
        if(lost.length) fails.push(`${form} prompt=${prompt} ${where} ${k} twice=${twice}: ${lost.length} statements lost, e.g. ${lost[0]}`);
      }
    }
    eq(fails, []);
  });

  it("recovers a brace config after a capture leaves a brace open", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("  AS path: 64512 {64513 64514\n" + CFG);
    eq(m.ifx.order.length, W.__parseConfig(CFG).ifx.order.length);
    eq(m.zones.length, W.__parseConfig(CFG).zones.length);
  });

  it("does not let a stray [ in a capture swallow the configuration after it", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("  Local Identity: ipv4_subnet(any:0,[0..7]=10.1.0.0/24\n" + CFG);
    eq(m.flat.length, W.__parseConfig(CFG).flat.length);
  });

  it("keeps operational output out of the configuration when prompts mark it", () => {
    const W = load("junos-config-report.html").window;
    eq(W.__parseConfig(WHOLE).stmtCount, W.__parseConfig(CFG).stmtCount);
  });

  it("reads configuration pasted straight after a capture with no prompt of its own", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("user@srx> show route\n" + OPER_ROUTES + "\n" + CFG);
    eq(m.zones.length, W.__parseConfig(CFG).zones.length);
    eq(m.opRouteCount, 3);
  });

  it("does not tag the configuration with a node from a capture's banner", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("node0:\n-----\n" + OPER_IKE + "\n" + CFG);
    ok(m.flat.every(r => r.node === ""));
    ok(m.zones.every(z => z.node === ""));
  });

  it("counts a repeat once even when a banner with no prompt tagged one copy", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig(CFG + "\n" + OPER_ROUTES + "\nnode0:\n-----\n" + OPER_SA + "\n" + OPER_ROUTES);
    eq(m.opRouteCount, 3);
    eq(m.opDuplicates.routes, 3);
  });

  it("still keeps the same route from two cluster nodes as two", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig("node0:\n-----\n" + OPER_ROUTES + "\nnode1:\n-----\n" + OPER_ROUTES);
    eq(m.opRouteCount, 6);
    eq(m.opDuplicates.routes, 0);
  });

  it("keeps captures that only look alike", () => {
    const W = load("junos-config-report.html").window;
    const other = `
inet.3: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

10.9.9.9/32        *[RSVP/7] 1d 00:00:01
                    >  via st0.0
`;
    const m = W.__parseConfig(CFG + OPER_ROUTES + "\n" + other);
    eq(m.opDuplicates.routes, 0, "a different table is not a duplicate");
    ok(m.tables.indexOf("inet.3") !== -1);
    ok(m.tables.indexOf("inet.0") !== -1);
  });

  it("reports the repeat as a finding rather than silently dropping it", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = WHOLE + "\nuser@srx> show route\n" + OPER_ROUTES;
    t.$("parseBtn").click();
    t.$("viewOverview").click();
    includes(t.text("ov"), "appears more than once in the input");
  });

  it("ticks off each optional command it found, and only those", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = CFG + "\n" + OPER_ROUTES + "\n" + OPER_IKE;
    t.$("parseBtn").click();
    eq(tick(t, "ckRoutes"), { on:true,  mark:"✓", found:"3 routes" });
    eq(tick(t, "ckSAs"),    { on:false, mark:"",       found:"not in the paste" });
    eq(tick(t, "ckIKE"),    { on:true,  mark:"✓", found:"2 SAs" });
    eq(tick(t, "ckHits"),   { on:false, mark:"",       found:"not in the paste" });
  });

  it("ticks nothing before a parse, or for a config with no captures", () => {
    const t = load("junos-config-report.html");
    eq(tick(t, "ckRoutes"), { on:false, mark:"", found:"" });
    t.$("raw").value = CFG;
    t.$("parseBtn").click();
    ["ckRoutes","ckSAs","ckIKE","ckHits"].forEach(id => eq(tick(t, id).on, false, id));
  });

  it("does not tick a capture that is there but unreadable", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = CFG + "\nuser@srx> show security ike security-associations detail\nerror: syntax error\n";
    t.$("parseBtn").click();
    eq(tick(t, "ckIKE").found, "not in the paste");
  });

  it("ticks every command from the sample, which is all one box", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    eq(t.errors, []);
    ["ckRoutes","ckSAs","ckIKE","ckHits"].forEach(id => ok(tick(t, id).on, id));
    includes(t.$("raw").value, "show security policies hit-count");
    eq(t.doc.querySelectorAll("textarea").length, 2, "the config box and the flow answer, nothing else");
    includes(t.text("srcline"), "ike security-associations");
  });

  it("copies a command", () => {
    const t = load("junos-config-report.html");
    let copied = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { copied = s; return Promise.resolve(); } } });
    t.doc.querySelector("#ckHits .copy").click();
    eq(copied, "show security policies hit-count");
  });

  it("clears the ticks", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("clearBtn").click();
    eq(t.$("raw").value, "");
    ["ckRoutes","ckSAs","ckIKE","ckHits"].forEach(id => eq(tick(t, id), { on:false, mark:"", found:"" }, id));
  });

  it("builds a report from captures alone, with no configuration at all", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = OPER_IKE;
    t.$("parseBtn").click();
    ok(!t.$("msg").classList.contains("on"), "live state on its own is still a report");
    t.$("viewVpn").click();
    includes(t.text("cards"), "gw-branch");
    includes(t.text("cards"), "phase 1 only");
  });

  itAsync("adds several opened files to the box, and appends to what is there", async () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = CFG;
    const input = t.$("fileInput");
    Object.defineProperty(input, "files", { configurable:true, value:[
      new t.window.File([OPER_ROUTES], "route.txt"),
      new t.window.File([OPER_IKE], "ike.txt")
    ]});
    input.dispatchEvent(new t.window.Event("change"));
    await until(() => t.text("fileNote").indexOf("ike.txt") !== -1);
    includes(t.text("fileNote"), "route.txt, ike.txt");
    includes(t.text("fileNote"), "Added to what was already in the box");
    includes(t.$("raw").value, "reth0");
    ok(tick(t, "ckRoutes").on && tick(t, "ckIKE").on);
    eq(t.errors, []);
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
    t.$("raw").value += "\n" + OPER_SA;
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
    t.$("raw").value += "\n" + OPER_SA;
    t.$("raw").value += "\n" + OPER_IKE.replace(/Gateway Name: gw-branch/, "Gateway Name: gw");
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
    t.$("raw").value += "\n" + OPER_SA;          // no configuration at all
    t.$("parseBtn").click();
    const out = lanes(t).filter(x => /outbound/.test(x.dir))[0];
    eq(out.width, "width:100%", "the longest in the capture fills the bar");
    includes(out.title, "scaled to the longest lifetime in this capture");
  });

  it("does not draw a bar for a phase 1 that reports no lifetime", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value += "\n" + OPER_IKE;
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
    for(const v of ["viewOverview","viewIfaces","viewZones","viewRoutes","viewDiagram","viewPolicies","viewVpn","viewFlow"]){
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

/* ------------------------------------------------------------------- flow -- */

const FLOW_CFG = `
system { host-name fw1; }
interfaces {
    reth0 { unit 0 { family inet { address 10.1.0.1/24; } } }
    reth1 { unit 0 { family inet { address 203.0.113.10/24; } } }
    reth3 { unit 0 { family inet6 { address 2001:db8:1::1/64; } } }
    st0 { unit 0 { family inet; } }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 203.0.113.254;
        route 10.20.0.0/16 next-hop 10.1.0.9;
        route 172.16.8.0/22 next-hop st0.0;
    }
}
security {
    ike { gateway gw { ike-policy p; address 198.51.100.77; external-interface reth1.0; } }
    ipsec { vpn half-open { bind-interface st0.0; ike { gateway gw; } } }
    zones {
        security-zone trust { interfaces { reth0.0; } }
        security-zone untrust { interfaces { reth1.0; } }
        security-zone vpn { interfaces { st0.0; } }
        security-zone dmz;
        functional-zone management { interfaces { fxp0.0; } }
    }
    policies {
        from-zone trust to-zone untrust {
            policy block-ftp {
                match { source-address any; destination-address any; application junos-ftp; }
                then { deny; }
            }
            policy allow-web {
                match { source-address any; destination-address any; application junos-https; }
                then { permit; }
            }
        }
        from-zone trust to-zone vpn {
            policy to-branch {
                match { source-address any; destination-address any; application any; }
                then { permit { tunnel { ipsec-vpn half-open; } } }
            }
        }
        default-policy { deny-all; }
    }
}`;

// One match-policies answer block, in the layout the device prints.
function mpBlock(o){
  const out = [
    `Policy: ${o.name}, action-type: ${o.action || "permit"}, State: ${o.state || "enabled"}, Index: ${o.index || 4}, Scope Policy: 0`,
    `  Policy Type: ${o.type || "Configured"}`,
    `  Sequence number: ${o.seq || 1}`,
    `  From zone: ${o.from || "trust"}, To zone: ${o.to || "untrust"}`,
    "  Source addresses:"
  ];
  (o.src || ["any-ipv4(global): 0.0.0.0/0"]).forEach(s => out.push("    " + s));
  out.push("  Destination addresses:");
  (o.dst || ["any-ipv4(global): 0.0.0.0/0"]).forEach(s => out.push("    " + s));
  (o.apps || [["junos-https", "tcp", "443-443"]]).forEach(a => {
    out.push(`  Application: ${a[0]}`,
             `    IP protocol: ${a[1]}, ALG: 0, Inactivity timeout: 1800`,
             "      Source port range: [0-0]",
             `      Destination port range: [${a[2]}]`);
  });
  out.push("  Per policy TCP Options: SYN check: No, SEQ check: No, Window scale: No");
  return out.join("\n");
}

const MP_CMD = "show security match-policies from-zone trust to-zone untrust source-ip 10.1.0.25 " +
               "destination-ip 192.0.2.80 source-port 1024 destination-port 443 protocol tcp";
const MP_PROMPT = "admin@fw1> " + MP_CMD;

// Parse a config, open the Flow view and fill the form. Zones are left for the route
// lookup unless given.
function flowPage(cfg, form, extra){
  const t = load("junos-config-report.html");
  t.$("raw").value = cfg;
  if(extra && extra.sas) t.$("raw").value += "\n" + extra.sas;
  t.$("parseBtn").click();
  t.$("viewFlow").click();
  setFlow(t, Object.assign({ src:"10.1.0.25", dst:"192.0.2.80", proto:"tcp", sport:"", dport:"443" }, form || {}));
  return t;
}
function setFlow(t, f){
  const ids = { src:"flowSrc", dst:"flowDst", sport:"flowSport", dport:"flowDport", proto:"flowProto", count:"flowCount", result:"flowResult" };
  for(const k of Object.keys(ids)){
    if(f[k] === undefined) continue;
    t.$(ids[k]).value = f[k];
    t.$(ids[k]).dispatchEvent(new t.window.Event("input"));
  }
  for(const [k, id] of [["from","flowFrom"], ["to","flowTo"]]){
    if(f[k] === undefined) continue;
    t.$(id).value = f[k];
    t.$(id).dispatchEvent(new t.window.Event("change"));
  }
}
const flowNotes = t => [...t.$("flowReport").querySelectorAll(".note")].map(n => ({
  level: ["bad","warn","info"].filter(l => n.classList.contains(l))[0] || "", text: n.textContent }));
function hasNote(t, level, re){
  const ns = flowNotes(t);
  ok(ns.some(n => n.level === level && re.test(n.text)),
     `expected a ${level} note matching ${re}, got: ${JSON.stringify(ns)}`);
}

describe("junos-config-report / match-policies parser", () => {
  const t = load("junos-config-report.html");
  const P = t.window.__parseMatchPolicies;
  const text = [MP_PROMPT + " result-count 2 | no-more", "node0:", "-----",
    mpBlock({ name:"allow-web", index:4, seq:1,
              src:["voice-vlan: 10.1.100.0/24", "10.1.0.0/24: 10.1.0.0/24"],
              dst:["any-ipv4(global): 0.0.0.0/0", "any-ipv6(global): ::/0"],
              apps:[["junos-http","tcp","80-80"], ["junos-https","tcp","443-443"]] }).replace(
      "  Source addresses:", "  Source vrf group:\n    any\n  Source addresses:"),
    "",
    mpBlock({ name:"allow-all-out", seq:2, index:5, apps:[["any","0","0-0"]] })].join("\n");
  const r = P(text);

  it("reads the command line out of the paste and drops a trailing pipe", () => {
    eq(r.query["from-zone"], "trust");
    eq(r.query["destination-ip"], "192.0.2.80");
    eq(r.query["result-count"], "2");
    ok(!/no-more|\|/.test(r.cmdLine), `the pipe must not survive: ${r.cmdLine}`);
    ok(/^show security match-policies from-zone trust/.test(r.cmdLine));
  });

  it("reads each policy block with its header fields", () => {
    eq(r.blocks.length, 2);
    const b = r.blocks[0];
    eq([b.name, b.action, b.state, b.index, b.seq, b.from, b.to, b.node, b.type],
       ["allow-web", "permit", "enabled", "4", "1", "trust", "untrust", "node0", "Configured"]);
  });

  it("reads address entries, splitting off the address-book name", () => {
    const b = r.blocks[0];
    eq(b.src.map(e => e.name), ["voice-vlan", "10.1.0.0/24"], "the vrf group 'any' is not a source address");
    eq(b.dst[0], { name:"any-ipv4", book:"global", addr:"0.0.0.0/0" });
  });

  it("reads applications and their port ranges", () => {
    const a = r.blocks[0].apps;
    eq(a.map(x => x.name), ["junos-http", "junos-https"]);
    eq(a[1].terms[0].protocol, "tcp");
    eq(a[1].terms[0].dport, [[443, 443]]);
    eq(a[1].terms[0].sport, [[0, 0]]);
  });

  it("keeps a multi-term application as separate terms", () => {
    const x = P(mpBlock({ name:"p" }).replace("  Per policy",
      "  Application: dns-both\n    IP protocol: udp, ALG: 0, Inactivity timeout: 60\n      Destination port range: [53-53]\n" +
      "    IP protocol: tcp, ALG: 0, Inactivity timeout: 1800\n      Destination port range: [53-53]\n  Per policy"));
    const app = x.blocks[0].apps.filter(a => a.name === "dns-both")[0];
    eq(app.terms.map(tm => tm.protocol), ["udp", "tcp"]);
  });

  it("reads ICMP information on an application", () => {
    const x = P(mpBlock({ name:"p", apps:[] }).replace("  Per policy",
      "  Application: junos-icmp-ping\n    IP protocol: icmp, ALG: 0, Inactivity timeout: 60\n      ICMP Information: type=8, code=0\n  Per policy"));
    eq(x.blocks[0].apps[0].terms[0].icmp, "type=8, code=0");
  });

  it("treats the first node's answer as the answer on a cluster", () => {
    const x = P(["node0:", "----", mpBlock({ name:"a" }), "", "node1:", "----", mpBlock({ name:"b" })].join("\n"));
    eq(x.nodes, ["node0", "node1"]);
    eq(x.blocks.length, 2);
    eq(x.primary.map(b => b.name), ["a"], "node1 is checked against node0, not appended to it");
  });

  it("collects error lines rather than reading them as policy", () => {
    const x = P(MP_PROMPT + "\nerror: Security zone 'untrsut' not found");
    eq(x.primary.length, 0);
    eq(x.errors, ["error: Security zone 'untrsut' not found"]);
    ok(x.query, "the command line is still read");
  });

  it("returns an empty result for garbage and for nothing", () => {
    const x = P("}}}}\nthis is not match-policies output");
    eq(x.blocks.length, 0);
    eq(x.lines, 2);
    eq(x.firstLine, "}}}}");
    eq(P("").blocks.length, 0);
    eq(P(null).blocks.length, 0);
  });
});

describe("junos-config-report / match-policies command", () => {
  const t = load("junos-config-report.html");
  const B = t.window.__buildMatchCommand;
  const full = { from:"trust", to:"untrust", src:"10.1.0.25", dst:"192.0.2.80", sport:"1024", dport:"443", proto:"tcp" };

  it("writes the command from a complete form", () => {
    const b = B(full);
    eq(b.cmd, MP_CMD);
    eq(b.missing, []);
    eq(b.problems, []);
    eq(B(Object.assign({}, full, { count:"4" })).cmd, MP_CMD + " result-count 4");
  });

  it("names what is missing and writes no command", () => {
    const b = B({ proto:"tcp" });
    eq(b.cmd, "");
    eq(b.missing, ["from-zone", "to-zone", "source-ip", "destination-ip", "destination-port"]);
  });

  it("refuses a prefix, since the command tests one flow", () => {
    const b = B(Object.assign({}, full, { dst:"192.0.2.0/24" }));
    eq(b.cmd, "");
    ok(b.problems.some(p => /is a prefix/.test(p)), JSON.stringify(b.problems));
  });

  it("refuses a malformed address and mixed address families", () => {
    ok(B(Object.assign({}, full, { src:"10.1.0.256" })).problems.some(p => /not an IPv4 or IPv6 address/.test(p)));
    ok(B(Object.assign({}, full, { dst:"2001:db8::1" })).problems.some(p => /different address families/.test(p)));
    eq(B(Object.assign({}, full, { src:"2001:db8:1::5", dst:"2001:db8::1" })).problems, [], "IPv6 on both sides is fine");
  });

  it("checks port and result-count ranges", () => {
    ok(B(Object.assign({}, full, { dport:"70000" })).problems.some(p => /destination-port 70000/.test(p)));
    ok(B(Object.assign({}, full, { sport:"0" })).problems.some(p => /source-port 0/.test(p)));
    ok(B(Object.assign({}, full, { count:"17" })).problems.some(p => /1 to 16/.test(p)));
    eq(B(Object.assign({}, full, { count:"16" })).problems, []);
  });

  it("fills a source port of 1024 for tcp and says so", () => {
    const b = B(Object.assign({}, full, { sport:"" }));
    ok(/source-port 1024 /.test(b.cmd));
    eq(b.auto, { sport:true });
    ok(b.notes.some(n => n.level === "info" && /1024/.test(n.text)));
  });

  it("uses placeholder ports for a protocol without ports", () => {
    const b = B(Object.assign({}, full, { proto:"ICMP", sport:"", dport:"" }));
    ok(/source-port 1 destination-port 1 protocol icmp$/.test(b.cmd), b.cmd);
    eq(b.auto, { sport:true, dport:true });
    ok(b.notes.some(n => /placeholder/.test(n.text)));
  });

  it("accepts a protocol number and refuses an unknown name", () => {
    ok(/protocol 50$/.test(B(Object.assign({}, full, { proto:"50", sport:"", dport:"" })).cmd));
    ok(B(Object.assign({}, full, { proto:"quic" })).problems.some(p => /not one this page knows/.test(p)));
    ok(B(Object.assign({}, full, { proto:"300" })).problems.length > 0, "a protocol number above 255 is refused");
  });
});

describe("junos-config-report / flow zone lookup", () => {
  const t = flowPage(FLOW_CFG, {});
  const Z = t.window.__zoneForAddress;

  it("finds the zone of a directly connected address", () => {
    const s = Z("10.1.0.25");
    eq(s.prefix, "10.1.0.0/24");
    eq(s.zones, ["trust"]);
    eq(s.table, "inet.0");
  });

  it("takes the longest match over the default route", () => {
    eq(Z("10.20.5.5").prefix, "10.20.0.0/16");
    eq(Z("10.20.5.5").zones, ["trust"]);
    eq(Z("192.0.2.80").prefix, "0.0.0.0/0");
    eq(Z("192.0.2.80").zones, ["untrust"]);
    eq(Z("172.16.9.1").zones, ["vpn"]);
  });

  it("recognises the firewall's own address", () => {
    eq(Z("203.0.113.10").own, "reth1.0");
  });

  it("looks in inet6.0 for an IPv6 address and admits when nothing covers it", () => {
    eq(Z("2001:db8:1::5").table, "inet6.0");
    eq(Z("2001:db8:1::5").zones, [], "reth3.0 is in no zone");
    eq(Z("2001:db8:ffff::1").legs, []);
  });

  it("returns null for something that is not an address", () => {
    eq(Z("not-an-ip"), null);
  });
});

describe("junos-config-report / flow view", () => {
  it("builds the sample question and reads the sample answer", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewFlow").click();
    eq(t.errors, []);
    ok(t.$("flow").classList.contains("on"));
    eq(t.$("viewFlow").getAttribute("aria-pressed"), "true");
    eq([t.$("flowFrom").value, t.$("flowTo").value], ["trust", "untrust"], "the zones come from the route lookup");
    ok(t.$("flowFromHint").classList.contains("known"));
    includes(t.text("flowToHint"), "0.0.0.0/0 via reth1.0");
    includes(t.text("flowCmd"), "result-count 2");
    ok(!t.$("flowCopy").disabled);
    eq(t.text("flowResState"), "2 policies returned");
    ok(t.$("flowReport").querySelector(".verdict.permit"), "the device said permit");
    includes(t.text("flowReport"), "allow-web");
    includes(t.text("flowReport"), "policy 1 of 3 in this zone pair");
    includes(t.text("flowReport"), "Also matches");
    includes(t.text("flowReport"), "allow-all-out");
  });

  it("marks which listed entry the flow fell inside", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewFlow").click();
    const chips = [...t.$("flowReport").querySelectorAll(".pchip")];
    const chip = s => chips.filter(c => c.textContent.indexOf(s) === 0)[0];
    ok(chip("10.1.0.0/24").classList.contains("addr"), "10.1.0.25 is inside 10.1.0.0/24");
    ok(chip("voice-vlan").classList.contains("any"), "10.1.0.25 is not inside the voice VLAN");
    ok(chip("junos-https").classList.contains("app"));
    ok(chip("junos-http ").classList.contains("any"), "port 80 does not cover a flow to 443");
  });

  it("offers only security zones, never functional ones", () => {
    const t = flowPage(FLOW_CFG, {});
    const opts = [...t.$("flowFrom").options].map(o => o.value).filter(Boolean);
    eq(opts, ["trust", "untrust", "vpn", "dmz"]);
  });

  it("says what is still needed and disables copy until the form is complete", () => {
    const t = flowPage(FLOW_CFG, { dst:"", dport:"" });
    ok(t.$("flowCmd").classList.contains("pending"));
    includes(t.text("flowCmd"), "Still needed: to-zone, destination-ip, destination-port");
    ok(t.$("flowCopy").disabled);
    // A prefix resolves to no zone, so pick one to leave the prefix as the only fault.
    setFlow(t, { dst:"192.0.2.0/24", dport:"443", to:"untrust" });
    includes(t.text("flowCmd"), "Fix the problem");
    includes(t.text("flowCmdNotes"), "is a prefix");
  });

  it("does not override a zone the engineer picked, and says where the route goes", () => {
    const t = flowPage(FLOW_CFG, {});
    eq(t.$("flowTo").value, "untrust");
    setFlow(t, { to:"dmz" });
    setFlow(t, { dst:"192.0.2.81" });
    eq(t.$("flowTo").value, "dmz", "a chosen zone must survive further typing");
    ok(t.$("flowToHint").classList.contains("warn"));
    includes(t.text("flowToHint"), "untrust, not dmz");
  });

  it("flags the firewall's own address rather than giving it a zone", () => {
    const t = flowPage(FLOW_CFG, { dst:"203.0.113.10" });
    eq(t.$("flowTo").value, "");
    includes(t.text("flowToHint"), "own address on reth1.0");
    includes(t.text("flowToHint"), "host-inbound");
  });

  it("reads a paste for a different flow as the answer to its own command", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT.replace("192.0.2.80", "192.0.2.99") + "\n" + mpBlock({ name:"allow-web", seq:2 }) });
    hasNote(t, "warn", /different flow than the form: destination-ip 192\.0\.2\.99 \(form: 192\.0\.2\.80\)/);
    includes(t.text("flowReport"), "192.0.2.99", "the flow shown is the pasted one");
  });

  it("does not count the page's own placeholder port as a disagreement", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT.replace("source-port 1024", "source-port 5000") + "\n" + mpBlock({ name:"allow-web", seq:2 }) });
    ok(!flowNotes(t).some(n => /different flow/.test(n.text)), JSON.stringify(flowNotes(t)));
  });

  it("says when the paste has no command line", () => {
    const t = flowPage(FLOW_CFG, { result: mpBlock({ name:"allow-web", seq:2 }) });
    hasNote(t, "info", /No command line in the paste/);
  });

  it("warns when none of the listed entries hold the flow", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT + "\n" +
      mpBlock({ name:"allow-web", seq:2, src:["lab: 10.9.0.0/16"], apps:[["junos-ssh","tcp","22-22"]] }) });
    hasNote(t, "warn", /None of the source addresses .* contain 10\.1\.0\.25/);
    hasNote(t, "warn", /None of the applications .* cover tcp\/443/);
  });

  it("flags a matched policy missing from the configuration", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT + "\n" + mpBlock({ name:"legacy-any" }) });
    hasNote(t, "warn", /legacy-any \(trust to untrust\) is not in the configuration paste/);
  });

  it("flags a device action that disagrees with the configuration", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT + "\n" + mpBlock({ name:"allow-web", action:"deny", seq:2 }) });
    hasNote(t, "bad", /matched allow-web with action deny, but the configuration paste says permit/);
    ok(t.$("flowReport").querySelector(".verdict.deny"), "the verdict is the device's, not the config's");
  });

  it("says when a deny comes ahead of a permit that would have passed the flow", () => {
    const t = flowPage(FLOW_CFG, { count:"2", result: MP_PROMPT + " result-count 2\n" +
      mpBlock({ name:"block-ftp", action:"deny", seq:1 }) + "\n\n" + mpBlock({ name:"allow-web", seq:2 }) });
    hasNote(t, "warn", /allow-web would also permit this flow but comes after block-ftp/);
  });

  it("explains a default-policy match from the zone pair's policies", () => {
    const t = flowPage(FLOW_CFG, { to:"dmz", result: MP_PROMPT.replace("untrust", "dmz") + "\n" +
      mpBlock({ name:"default-policy", action:"deny", type:"Default", from:"trust", to:"dmz", seq:0 }) });
    ok(t.$("flowReport").querySelector(".verdict.deny"));
    includes(t.text("flowReport"), "No policy matched");
    hasNote(t, "info", /no policy from trust to dmz at all/);
    ok(!flowNotes(t).some(n => /None of the/.test(n.text)), "a default match lists no entries to miss");
  });

  it("flags a default action that contradicts the configured default-policy", () => {
    const t = flowPage(FLOW_CFG, { to:"dmz", result: MP_PROMPT.replace("untrust", "dmz") + "\n" +
      mpBlock({ name:"default-policy", action:"permit", type:"Default", from:"trust", to:"dmz", seq:0 }) });
    hasNote(t, "bad", /default permit, but the configuration paste says default-policy deny-all/);
  });

  it("warns when the returned policy is for another zone pair", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT + "\n" + mpBlock({ name:"to-branch", from:"trust", to:"vpn" }) });
    hasNote(t, "warn", /Asked about trust to untrust, but the policy returned is from trust to vpn/);
  });

  it("flags a permit into a tunnel whose SA is not up", () => {
    // OPER_SA holds VPN half-open with its outbound SA not installed.
    const t = flowPage(FLOW_CFG, { dst:"172.16.9.1", result:
      MP_PROMPT.replace("untrust", "vpn").replace("192.0.2.80", "172.16.9.1") + "\n" +
      mpBlock({ name:"to-branch", to:"vpn" }) }, { sas: OPER_SA });
    eq(t.$("flowTo").value, "vpn");
    includes(t.text("flowReport"), "into IPsec VPN half-open");
    hasNote(t, "bad", /Permitted into IPsec VPN half-open, whose SA is .* not up/);
  });

  it("flags cluster nodes that disagree", () => {
    const t = flowPage(FLOW_CFG, { result: [MP_PROMPT, "node0:", "----", mpBlock({ name:"allow-web", seq:2 }),
      "", "node1:", "----", mpBlock({ name:"block-ftp", action:"deny" })].join("\n") });
    includes(t.text("flowResState"), "node0, node1");
    hasNote(t, "bad", /node1 answered block-ftp \(deny\) where node0 answered allow-web \(permit\)/);
  });

  it("reports what it saw when the answer is an error or not match-policies at all", () => {
    const t = flowPage(FLOW_CFG, { result: MP_PROMPT + "\nerror: Security zone 'untrsut' not found" });
    eq(t.text("flowResState"), "nothing recognised");
    includes(t.text("flowReport"), "returned an error rather than a policy");
    includes(t.text("flowReport"), "untrsut");
    setFlow(t, { result: "Session ID: 12345, Policy name: allow-web/4, Timeout: 1800" });
    includes(t.text("flowReport"), "found no Policy: line");
    includes(t.text("flowReport"), "First line seen: Session ID: 12345");
    setFlow(t, { result: "" });
    eq(t.text("flowResState"), "waiting");
    eq(t.text("flowReport"), "");
  });

  it("escapes everything it reads out of the paste", () => {
    const t = flowPage(FLOW_CFG, { result: mpBlock({ name:"<img src=x onerror=alert(1)>",
      src:["<b>x</b>: 10.1.0.0/24"] }) });
    eq(t.$("flowReport").querySelector("img"), null);
    eq(t.$("flowReport").querySelector(".pchip b"), null);
    includes(t.text("flowReport"), "<img src=x onerror=alert(1)>");
    eq(t.errors, []);
  });

  it("exports the answer as CSV and Markdown", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewFlow").click();
    const got = [];
    t.window.HTMLAnchorElement.prototype.click = function(){ got.push({ name:this.download, href:this.href }); };
    t.$("csvBtn").click();
    eq(got[0].name, "edge-srx-01-flow-match.csv");
    const csv = decodeURIComponent(got[0].href.split(",").slice(1).join(","));
    const rows = csv.split("\n");
    eq(rows.length, 3);
    includes(rows[0], '"Policy"');
    includes(rows[1], '"allow-web"');
    includes(rows[1], '"matched"');
    includes(rows[2], '"never reached"');

    let md = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { md = s; return Promise.resolve(); } } });
    t.$("mdBtn").click();
    includes(md, "Flow: `show security match-policies from-zone trust to-zone untrust");
    includes(md, "**permit** by allow-web");
    includes(md, "| 1 | allow-web | trust | untrust | permit |");
    eq(t.errors, []);
  });

  it("copies the command it wrote", () => {
    const t = flowPage(FLOW_CFG, {});
    let copied = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { copied = s; return Promise.resolve(); } } });
    t.$("flowCopy").click();
    eq(copied, MP_CMD);
  });

  it("clears the form and the answer", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewFlow").click();
    t.$("clearBtn").click();
    for(const id of ["flowSrc","flowDst","flowSport","flowDport","flowCount","flowResult","flowFrom","flowTo"]) eq(t.$(id).value, "", id);
    eq(t.$("flowProto").value, "tcp");
    ok(!t.$("flow").classList.contains("on"));
    eq(t.text("flowReport"), "");
    eq(t.text("flowResState"), "waiting");
    ok(t.$("flowCopy").disabled);
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

/* ---------------------------------------------------------------- logging -- */

const MGMT_IF = `
interfaces { fxp0 { unit 0 { family inet { address 192.168.250.10/24; } } } }`;

const LOG_BRACE = `
system {
    syslog {
        host 10.1.0.60 {
            any any;
            match "RT_FLOW_SESSION";
            port 5514;
        }
        file messages {
            any notice;
        }
    }
}
security {
    log {
        mode stream;
        format sd-syslog;
        source-address 10.1.0.1;
        stream siem {
            category [ all ];
            host {
                10.1.0.50;
                port 514;
            }
        }
        stream noc {
            severity warning;
            host {
                192.168.250.60;
            }
        }
    }
}`;

const LOG_SET = `
set system syslog host 10.1.0.60 any any
set system syslog host 10.1.0.60 match RT_FLOW_SESSION
set system syslog host 10.1.0.60 port 5514
set system syslog file messages any notice
set security log mode stream
set security log format sd-syslog
set security log source-address 10.1.0.1
set security log stream siem category all
set security log stream siem host 10.1.0.50
set security log stream siem host port 514
set security log stream noc severity warning
set security log stream noc host 192.168.250.60`;

const LOG_POLICIES = `
security {
    zones {
        security-zone trust { interfaces { reth0.0; } }
        security-zone untrust { interfaces { reth1.0; } }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match { source-address any; destination-address any; application junos-https; }
                then { permit; log { session-init; } }
            }
            policy allow-all {
                match { source-address any; destination-address any; application any; }
                then { permit; log { session-close; } }
            }
        }
        from-zone untrust to-zone trust {
            policy block {
                match { source-address any; destination-address any; application any; }
                then { deny; log { session-close; } }
            }
        }
    }
}`;

const HITS = `
Logical system: root-logical-system
 Index   From zone        To zone           Name           Policy count  Action
 1       trust            untrust           allow-web      1520          Permit
 2       trust            untrust           allow-all      77            Permit
 3       untrust          trust             block          48211         Deny

Number of policy: 3`;

const HITS_CLUSTER = `
node0:
--------------------------------------------------------------------------
Logical system: root-logical-system
 Index   From zone        To zone           Name           Policy count  Action
 3       untrust          trust             block          40000         Deny
 9       untrust          trust             from-a-group   12            Deny

node1:
--------------------------------------------------------------------------
Logical system: root-logical-system
 Index   From zone        To zone           Name           Policy count  Action
 3       untrust          trust             block          211           Deny`;

function logNotes(m){
  const L = m.logging;
  let out = L.notes.slice();
  L.sec.streams.forEach(s => { out = out.concat(s.notes); });
  L.syslog.dests.forEach(d => { out = out.concat(d.notes); });
  L.rows.forEach(r => { out = out.concat(r.notes); });
  return out;
}
function hasLogNote(m, level, re){
  const ns = logNotes(m);
  ok(ns.some(n => n.level === level && re.test(n.text)),
     `expected a ${level} note matching ${re}, got: ${JSON.stringify(ns.map(n => n.level + ": " + n.text))}`);
}
function noLogNote(m, re){
  const ns = logNotes(m);
  ok(!ns.some(n => re.test(n.text)), `did not expect a note matching ${re}, got: ${JSON.stringify(ns.map(n => n.text))}`);
}

describe("junos-config-report / logging parser", () => {
  const W = load("junos-config-report.html").window;

  it("reads streams and syslog destinations the same from brace and set form", () => {
    const a = W.__parseLogging(LOG_BRACE), b = W.__parseLogging(LOG_SET);
    const shape = L => ({
      mode: L.sec.mode, format: L.sec.format, src: L.sec.sourceAddress,
      streams: L.sec.streams.map(s => [s.name, s.host, s.port, s.severity, s.categories]),
      dests: L.syslog.dests.map(d => [d.kind, d.name, d.port, d.levels, d.match])
    });
    eq(shape(a), shape(b));
    eq(shape(a).streams, [["siem","10.1.0.50","514","",["all"]], ["noc","192.168.250.60","","warning",[]]]);
    eq(a.syslog.dests[0].levels, [{facility:"any", severity:"any"}]);
    eq(a.syslog.dests[0].match, ["RT_FLOW_SESSION"]);
  });

  it("joins a stream host to the interface and zone it leaves by", () => {
    const m = W.__parseConfig(IFACES + MGMT_IF + BRACE_ZONES + LOG_BRACE);
    const siem = m.logging.sec.streams.find(s => s.name === "siem");
    eq(siem.path.ifaces, ["reth0.0"]);
    eq(siem.path.zones, ["trust"]);
    eq(siem.sessions, "yes");
    eq(m.logging.sec.sourceIf, "reth0.0");
  });

  it("warns when a stream can only leave through fxp0", () => {
    const m = W.__parseConfig(IFACES + MGMT_IF + BRACE_ZONES + LOG_BRACE);
    const noc = m.logging.sec.streams.find(s => s.name === "noc");
    ok(noc.path.mgmt);
    ok(noc.notes.some(n => n.level === "warn" && /management port/.test(n.text)));
  });

  it("says a stream filtered above info never carries session logs", () => {
    const m = W.__parseConfig(LOG_BRACE);
    const noc = m.logging.sec.streams.find(s => s.name === "noc");
    eq(noc.sessions, "no");
    hasLogNote(m, "warn", /severity warning\. Session logs are sent at info/);
  });

  it("says system syslog sees no session logs in stream mode", () => {
    const m = W.__parseConfig(LOG_BRACE);
    m.logging.syslog.dests.forEach(d => eq(d.sessions, "no", d.name));
  });

  it("reads event mode through system syslog, and flags streams it ignores", () => {
    const cfg = LOG_SET.replace("mode stream", "mode event");
    const m = W.__parseConfig(cfg);
    const host = m.logging.syslog.dests.find(d => d.name === "10.1.0.60");
    eq(host.sessions, "yes", "any any with an RT_FLOW match takes session logs");
    eq(m.logging.syslog.dests.find(d => d.name === "messages").sessions, "no", "any notice drops info");
    m.logging.sec.streams.forEach(s => eq(s.sessions, "no"));
    hasLogNote(m, "warn", /Mode is event, so 2 configured streams are not used/);
  });

  it("calls a syslog match that does not name RT_FLOW filtered, not absent", () => {
    const m = W.__parseConfig(`
set security log mode event
set system syslog file traffic any any
set system syslog file traffic match "IDP_ATTACK"`);
    eq(m.logging.syslog.dests[0].sessions, "filtered");
    hasLogNote(m, "info", /does not name RT_FLOW/);
  });

  it("leaves the mode undecided rather than guessing a platform default", () => {
    const m = W.__parseConfig(`set security log stream s host 10.1.0.50` + IFACES);
    eq(m.logging.sec.mode, "");
    eq(m.logging.sec.streams[0].sessions, "maybe");
    hasLogNote(m, "info", /No security log mode is set/);
  });

  it("warns when stream mode has no source address", () => {
    const m = W.__parseConfig(`
set security log mode stream
set security log stream s host 10.1.0.50`);
    hasLogNote(m, "warn", /Stream mode with no security log source-address/);
  });

  it("warns when the source address is on no interface", () => {
    const m = W.__parseConfig(IFACES + `
set security log mode stream
set security log source-address 10.9.9.9
set security log stream s host 10.1.0.50`);
    hasLogNote(m, "warn", /source-address 10\.9\.9\.9 is not configured on any interface/);
  });

  it("does not call logs lost when the paste has no logging hierarchy at all", () => {
    const m = W.__parseConfig(LOG_POLICIES);
    noLogNote(m, /nothing in this paste sends them anywhere/);
    hasLogNote(m, "info", /No security log and no system syslog in this paste/);
  });

  it("warns when policies log and nothing receives it", () => {
    const m = W.__parseConfig(IFACES + LOG_POLICIES + `
set security log mode event
set system syslog file messages any notice`);
    hasLogNote(m, "warn", /ask for session logs, but nothing in this paste sends them anywhere/);
  });

  it("flags a stream host with no route, softened when a dynamic protocol could supply one", () => {
    const base = IFACES + `
set security log mode stream
set security log source-address 10.1.0.1
set security log stream s host 198.18.0.5`;
    hasLogNote(W.__parseConfig(base), "warn", /No route in inet\.0 covers 198\.18\.0\.5/);
    hasLogNote(W.__parseConfig(base + "\nset protocols ospf area 0 interface reth0.0"), "info", /may be learned through ospf/);
  });

  it("looks a host up in its own routing instance", () => {
    const m = W.__parseConfig(IFACES + `
set routing-instances MGMT instance-type virtual-router
set routing-instances MGMT interface reth1.0
set security log mode stream
set security log source-address 10.1.0.1
set security log stream s host 203.0.113.80
set security log stream s host routing-instance MGMT`);
    const s = m.logging.sec.streams[0];
    eq(s.routingInstance, "MGMT");
    eq(s.path.table, "MGMT.inet.0");
  });

  it("warns that session-close on a deny never fires", () => {
    const m = W.__parseConfig(LOG_POLICIES);
    const r = m.logging.rows.find(r => r.p.name === "block");
    ok(r.close && !r.init);
    ok(r.notes.some(n => n.level === "warn" && /no close to log/.test(n.text)));
  });

  it("notes a permit that logs the open only", () => {
    const m = W.__parseConfig(LOG_POLICIES);
    const r = m.logging.rows.find(r => r.p.name === "allow-web");
    ok(r.notes.some(n => /Logs the open only/.test(n.text)));
  });

  it("reports zone pairs whose fall-through to the default policy goes unlogged", () => {
    const m = W.__parseConfig(LOG_POLICIES);
    eq(m.logging.unloggedPairs, ["untrust trust"], "trust->untrust ends in a catch-all permit");
    hasLogNote(m, "info", /1 of 2 zone pairs end without a logged catch-all deny/);
  });

  it("counts a global logged catch-all deny as covering every pair", () => {
    const m = W.__parseConfig(LOG_POLICIES + `
set security policies global policy last match source-address any
set security policies global policy last match destination-address any
set security policies global policy last match application any
set security policies global policy last then deny
set security policies global policy last then log session-init`);
    noLogNote(m, /logged catch-all deny/);
  });

  it("marks a destination inactive only when all of it is", () => {
    const m = W.__parseConfig(`
set system syslog host 10.1.0.60 any any
deactivate system syslog host 10.1.0.60 port
set system syslog host 10.1.0.70 any any
deactivate system syslog host 10.1.0.70`);
    const d = m.logging.syslog.dests;
    eq(d.find(x => x.name === "10.1.0.60").inactive, false);
    eq(d.find(x => x.name === "10.1.0.70").inactive, true);
    const b = W.__parseConfig(`security { log { inactive: stream s { host { 10.1.0.50; } } } }`);
    eq(b.logging.sec.streams[0].inactive, true, "brace form inactive: reaches every child");
  });
});

describe("junos-config-report / one-shot commands and files", () => {
  const P = "user@srx> ";
  const SESSION = [
    P + "set cli screen-length 0", "Screen length set to 0",
    P + "set cli screen-width 1024", "Screen width set to 1024",
    P + "show configuration | display inheritance", IFACES + STATICS + BRACE_ZONES,
    P + "show route", OPER_ROUTES,
    P + "show security ipsec security-associations detail", OPER_SA,
    P + "show security ike security-associations detail", OPER_IKE,
    P + "show security policies hit-count", HITS,
    P
  ].join("\n");
  const shape = m => ({ ifaces: m.ifx.order.length, zones: m.zones.length, stmts: m.stmtCount, op: m.opRouteCount,
                        sas: m.sas.length, ikes: m.ikes.length, hits: m.hitRows.length });

  it("lists every command once, paging and wrapping off first", () => {
    const t = load("junos-config-report.html");
    const lines = t.text("allCmds").split("\n");
    eq(lines.slice(0, 3), ["set cli screen-length 0", "set cli screen-width 1024", "show configuration | display inheritance"]);
    eq(lines.slice(3), Array.from(t.doc.querySelectorAll(".ck[data-cmd]")).map(e => e.getAttribute("data-cmd")),
       "the block and the checklist name the same commands");
  });

  it("copies the whole block", () => {
    const t = load("junos-config-report.html");
    let copied = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { copied = s; return Promise.resolve(); } } });
    t.$("copyAll").click();
    eq(copied, t.text("allCmds") + "\n");
  });

  it("reads what the one-shot block prints as if each capture were pasted on its own", () => {
    const W = load("junos-config-report.html").window;
    const m = W.__parseConfig(SESSION);
    eq(shape(m), shape(W.__parseConfig([IFACES + STATICS + BRACE_ZONES, OPER_ROUTES, OPER_SA, OPER_IKE, HITS].join("\n"))));
    eq(m.stmtCount, W.__parseConfig(IFACES + STATICS + BRACE_ZONES).stmtCount, "the set cli echoes are not config");
  });

  it("reads a saved terminal log the same as a clean paste", () => {
    const W = load("junos-config-report.html").window;
    const want = shape(W.__parseConfig(SESSION));
    const lines = SESSION.split("\n");
    const logs = {
      bom:   "﻿" + SESSION,
      crlf:  SESSION.replace(/\n/g, "\r\n"),
      ansi:  lines.map((l, i) => i % 5 === 2 ? "\x1b[K\x1b[0m" + l : l).join("\n"),
      nul:   SESSION.replace(/\n/g, "\n\x00"),
      pager: lines.map((l, i) => i % 9 === 8 ? "---(more 42%)---\r                \r" + l : l).join("\n"),
      bs:    SESSION.replace(P + "show route", P + "show rou\b\b\broute"),
      title: "\x1b]0;user@srx: ~\x07" + SESSION
    };
    for(const [k, v] of Object.entries(logs)) eq(shape(W.__parseConfig(v)), want, k);
  });

  itAsync("reads an opened session log, artefacts and all, like a paste", async () => {
    const t = load("junos-config-report.html");
    const input = t.$("fileInput");
    const log = "﻿" + SESSION.replace(/\n/g, "\r\n").replace(/\r\n/g, (m, i) => i % 3 ? m : "\x1b[K" + m);
    Object.defineProperty(input, "files", { configurable:true, value:[ new t.window.File([log], "session.log") ] });
    input.dispatchEvent(new t.window.Event("change"));
    await until(() => t.text("fileNote").indexOf("session.log") !== -1);
    const want = shape(t.window.__parseConfig(SESSION));
    eq(shape(t.window.__parseConfig(t.$("raw").value)), want);
    ["ckRoutes","ckSAs","ckIKE","ckHits"].forEach(id => ok(t.$(id).classList.contains("on"), id));
    eq(t.errors, []);
  });

  itAsync("adds a dropped file to what is already in the box", async () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + STATICS + BRACE_ZONES;
    const ev = new t.window.Event("drop", { bubbles:true, cancelable:true });
    Object.defineProperty(ev, "dataTransfer", { value:{ files:[ new t.window.File([P + "show route\n" + OPER_ROUTES], "route.txt") ] } });
    t.$("drop").dispatchEvent(ev);
    await until(() => t.text("fileNote").indexOf("route.txt") !== -1);
    includes(t.text("fileNote"), "Added to what was already in the box");
    ok(t.$("ckRoutes").classList.contains("on"));
    ok(t.$("raw").value.indexOf("reth0") !== -1, "the config is still there");
  });

  itAsync("parses all of a file too large to edit, and says so", async () => {
    const t = load("junos-config-report.html");
    const filler = Array(90000).fill("## " + "x".repeat(44)).join("\n");      // ~4.2 MB of comment lines
    const big = IFACES + STATICS + BRACE_ZONES + "\n" + filler + "\n" + P + "show route\n" + OPER_ROUTES;
    ok(big.length > 4000000);
    const input = t.$("fileInput");
    Object.defineProperty(input, "files", { configurable:true, value:[ new t.window.File([big], "rsi.txt") ] });
    input.dispatchEvent(new t.window.Event("change"));
    await until(() => t.text("fileNote").indexOf("rsi.txt") !== -1, 10000);
    includes(t.text("fileNote"), "Too large to edit here");
    ok(t.$("raw").hasAttribute("readonly"));
    ok(t.$("ckRoutes").classList.contains("on"), "the capture at the far end of the file was read");
    ok(t.$("raw").value.length < big.length, "only the head is shown");
  });
});

describe("junos-config-report / config groups", () => {
  const W = load("junos-config-report.html").window;
  const LOG_GROUP = `
set groups LOG security policies from-zone <*> to-zone <*> policy <*> then log session-close`;
  const row = (m, name) => m.logging.rows.find(r => r.p.name === name);

  it("applies a wildcard logging group to every policy and says where it came from", () => {
    const m = W.__parseConfig(LOG_POLICIES + LOG_GROUP + "\nset apply-groups LOG");
    eq(row(m, "allow-web").close, true);
    eq(row(m, "allow-web").closeFrom, "LOG");
    eq(row(m, "allow-all").closeFrom, "", "configured explicitly, so not credited to the group");
    eq(m.groupInfo.inherited, 1);
    hasLogNote(m, "info", /1 policy logs because of group LOG/);
  });

  it("does nothing with a group that is never applied, and says so", () => {
    const m = W.__parseConfig(LOG_POLICIES + LOG_GROUP);
    eq(row(m, "allow-web").close, false);
    eq(m.groupInfo.unapplied, ["LOG"]);
    hasLogNote(m, "warn", /Group LOG sets policy logging but reaches no policy/);
  });

  it("lets a wildcard match only what the configuration has, never create it", () => {
    const m = W.__parseConfig(LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone dmz policy <*> then log session-init
set apply-groups G`);
    eq(m.policies.length, 3);
    eq(m.groupInfo.inherited, 0);
  });

  it("matches a partial wildcard", () => {
    const m = W.__parseConfig(LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone <*> policy <allow-*> then log session-init
set apply-groups G`);
    eq(row(m, "allow-all").initFrom, "G");
    eq(row(m, "block").init, false);
  });

  it("creates what a group names outright", () => {
    const m = W.__parseConfig(`
set groups BASE system syslog host 10.9.9.9 any any
set apply-groups BASE`);
    const d = m.logging.syslog.dests.find(x => x.name === "10.9.9.9");
    ok(d, "the syslog host comes from the group");
    eq(d.from, ["BASE"]);
  });

  it("keeps an explicit value over an inherited one, and an earlier group over a later one", () => {
    const explicitWins = W.__parseConfig(`
set security log mode event
set groups A security log mode stream
set apply-groups A`);
    eq(explicitWins.logging.sec.mode, "event");
    const firstGroupWins = W.__parseConfig(`
set groups A security log mode stream
set groups B security log mode event
set apply-groups [ A B ]`);
    eq(firstGroupWins.logging.sec.mode, "stream");
    const sev = W.__parseConfig(`
set system syslog file messages any notice
set groups A system syslog file messages any any
set apply-groups A`);
    eq(sev.logging.syslog.dests[0].levels, [{facility:"any", severity:"notice"}], "one severity per facility, explicit wins");
  });

  it("merges flags rather than replacing them", () => {
    const m = W.__parseConfig(LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone <*> policy <*> then log session-init
set apply-groups G`);
    const r = row(m, "allow-all");
    ok(r.init && r.close, "explicit session-close and inherited session-init both stand");
  });

  it("applies a group set below the top only to that subtree", () => {
    const m = W.__parseConfig(LOG_POLICIES + LOG_GROUP +
      "\nset security policies from-zone trust to-zone untrust apply-groups LOG");
    eq(row(m, "allow-web").closeFrom, "LOG");
    eq(row(m, "block").closeFrom, "");
    eq(m.groupInfo.inherited, 1);
  });

  it("honours apply-groups-except", () => {
    const m = W.__parseConfig(LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone <*> policy <*> then log session-init
set apply-groups G
set security policies from-zone untrust to-zone trust policy block apply-groups-except G`);
    eq(row(m, "allow-web").init, true);
    eq(row(m, "block").init, false);
  });

  it("does not apply an inactive group or an inactive apply-groups", () => {
    const a = W.__parseConfig(LOG_POLICIES + LOG_GROUP + "\nset apply-groups LOG\ndeactivate apply-groups LOG");
    eq(row(a, "allow-web").close, false);
    const b = W.__parseConfig(LOG_POLICIES + "\ngroups { inactive: LOG { security { policies { from-zone <*> to-zone <*> { policy <*> { then { log { session-close; } } } } } } } }\nset apply-groups LOG");
    eq(row(b, "allow-web").close, false);
  });

  it("leaves ${node} alone and does not call node groups unapplied", () => {
    const m = W.__parseConfig(`
set groups node0 system host-name fw-a
set groups node1 system host-name fw-b
set apply-groups "\${node}"`);
    eq(m.host, "");
    ok(m.groupInfo.nodeGroup);
    eq(m.groupInfo.unapplied, []);
  });

  it("adds nothing twice to display inheritance output, and does not call the group idle", () => {
    const inherited = W.__parseConfig(LOG_POLICIES + LOG_GROUP + "\nset apply-groups LOG");
    // What the device prints: the inherited statement written out, the group still there.
    const shown = LOG_POLICIES + `
## 'session-close' was inherited from group 'LOG'
set security policies from-zone trust to-zone untrust policy allow-web then log session-close` + LOG_GROUP + "\nset apply-groups LOG";
    const m = W.__parseConfig(shown);
    eq(m.groupInfo.inherited, 0);
    eq(row(m, "allow-web").close, true);
    eq(m.policies.length, inherited.policies.length);
    noLogNote(m, /reaches no policy/);
  });

  it("still keeps a group's own template out of the report", () => {
    const m = W.__parseConfig(`groups { node0 { security { zones { security-zone ghost { interfaces { ge-0/0/0.0; } } } } } }`);
    eq(m.zones.length, 0);
  });

  function policyRow(t, name){
    const tr = Array.from(t.doc.querySelectorAll("#table tbody tr")).find(r => r.children[3] && r.children[3].textContent.indexOf(name) === 0);
    ok(tr, "row for " + name);
    return tr;
  }
  function logCell(t, name){
    const tr = policyRow(t, name);
    return tr.children[tr.children.length - 1];
  }

  it("shows in the Policies view whether each policy logs, inherited flags included", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone <*> policy <allow-*> then log session-close
set apply-groups G`;
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    eq(t.doc.querySelector("#table thead tr").lastChild.textContent, "Logging");

    // Each line says what is recorded, then the keyword, then the marker if inherited.
    const lines = cell => Array.from(cell.querySelectorAll(".logline")).map(l => ({
      what: l.querySelector(".what").textContent,
      kw:   (l.querySelector(".kw") || {}).textContent || "",
      inh:  (l.querySelector(".inh") || {}).textContent || ""
    }));
    eq(lines(logCell(t, "allow-web")), [
      { what:"session start",       kw:"session-init",  inh:"" },
      { what:"session end + bytes", kw:"session-close", inh:"inherited \u00b7 G" }
    ]);
    includes(logCell(t, "allow-web").querySelector(".inh").getAttribute("title"), "Inherited from config group G");
    eq(lines(logCell(t, "allow-all")), [{ what:"session end + bytes", kw:"session-close", inh:"" }],
       "configured explicitly, so not marked inherited");
    eq(t.errors, []);
  });

  it("does not show logging from a group that is not applied", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES + LOG_GROUP;
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    excludes(logCell(t, "allow-web").textContent, "session-close");
  });

  it("calls out a deny that records nothing", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES;
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    const block = logCell(t, "block");
    includes(block.textContent, "never fires on a deny");
    includes(block.textContent, "drops not logged");
    eq(block.querySelectorAll(".logline.warn").length, 2, "both lines highlighted as warnings");
    excludes(policyRow(t, "block").textContent, "+log", "the action column no longer carries it");
  });

  it("says not logged when a policy logs nothing", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + `
set security policies from-zone trust to-zone untrust policy quiet match source-address any
set security policies from-zone trust to-zone untrust policy quiet match destination-address any
set security policies from-zone trust to-zone untrust policy quiet match application any
set security policies from-zone trust to-zone untrust policy quiet then permit`;
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    eq(logCell(t, "quiet").textContent, "not logged");
  });

  it("filters policies by what they log and by the group it came from", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES + `
set groups G security policies from-zone <*> to-zone <*> policy <allow-web> then log session-close
set apply-groups G`;
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    t.$("filter").value = "inherited from G";
    t.$("filter").dispatchEvent(new t.window.Event("input"));
    includes(t.text("table"), "allow-web");
    excludes(t.text("table"), "allow-all");
  });

  it("exports the logging column", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES + LOG_GROUP + "\nset apply-groups LOG";
    t.$("parseBtn").click();
    t.$("viewPolicies").click();
    const got = [];
    t.window.HTMLAnchorElement.prototype.click = function(){ got.push({ name:this.download, href:this.href }); };
    t.$("csvBtn").click();
    const csv = decodeURIComponent(got[0].href.split(",").slice(1).join(","));
    includes(csv.split("\n")[0], '"Action","Logging"');
    includes(csv, '"session start [session-init]; session end + bytes [session-close, inherited from LOG]"');
    includes(csv, '"never fires on a deny [session-close]; drops not logged"');
    let md = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { md = s; return Promise.resolve(); } } });
    t.$("mdBtn").click();
    includes(md, "| Action | Logging |");
  });

  it("shows the group beside the log flag in the logging view", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = IFACES + LOG_POLICIES + LOG_GROUP + "\nset apply-groups LOG";
    t.$("parseBtn").click();
    t.$("viewLogging").click();
    ok(t.doc.querySelector("#cards .inh"), "the same inherited marker as the Policies view");
    includes(t.doc.querySelector("#cards .inh").textContent, "LOG");
    t.$("viewOverview").click();
    includes(t.text("ov"), "Statements inherited from groups");
    eq(t.errors, []);
  });
});

describe("junos-config-report / policy hit counts", () => {
  const W = load("junos-config-report.html").window;

  it("parses the hit-count table", () => {
    const h = W.__parseHitCount(HITS);
    eq(h.length, 3);
    eq(h[2], { node:"", lsys:"root-logical-system", index:"3", from:"untrust", to:"trust",
               name:"block", count:48211, action:"deny" });
  });

  it("reads nothing out of a configuration", () => {
    eq(W.__parseHitCount(LOG_POLICIES + LOG_SET + IFACES).length, 0);
  });

  it("joins hit counts onto policies and flags unlogged drops", () => {
    const m = W.__parseConfig(LOG_POLICIES + "\n" + HITS);
    const r = m.logging.rows.find(r => r.p.name === "block");
    eq(r.hits, 48211);
    ok(r.notes.some(n => /48211 lookups hit this deny/.test(n.text)));
    eq(m.logging.hitTotal, 1520 + 77 + 48211);
  });

  it("sums cluster nodes and names policies the config does not have", () => {
    const m = W.__parseConfig(LOG_POLICIES + "\n" + HITS_CLUSTER);
    const r = m.logging.rows.find(r => r.p.name === "block");
    eq(r.hits, 40211);
    eq(r.nodes, { node0: 40000, node1: 211 });
    eq(m.logging.stray, ["from-a-group"]);
    hasLogNote(m, "info", /names 1 policy this configuration does not have: from-a-group/);
  });

  it("reads hit counts wherever they sit in the box, and counts a repeat once", () => {
    const shape = m => ({ hits: m.hitRows.length, total: m.logging.hitTotal,
                          rows: m.logging.rows.map(r => r.hits) });
    const after  = shape(W.__parseConfig(LOG_POLICIES + "\n" + HITS));
    const before = shape(W.__parseConfig("user@srx> show security policies hit-count\n" + HITS + "\n" + LOG_POLICIES));
    const twice  = W.__parseConfig(LOG_POLICIES + "\n" + HITS + "\n" + HITS);
    eq(before, after);
    eq(shape(twice), after, "pasting it twice must not double the counts");
    eq(twice.opDuplicates.hits, 3);
  });
});

describe("junos-config-report / logging DOM", () => {
  it("renders the logging view from the sample", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewLogging").click();
    eq(t.errors, []);
    eq(t.$("viewLogging").getAttribute("aria-pressed"), "true");
    const txt = t.text("cards");
    includes(txt, "Session logs");
    includes(txt, "Security log streams");
    includes(txt, "System syslog");
    includes(txt, "What each policy logs");
    includes(txt, "10.1.0.50:514");
    includes(txt, "via reth0.0");
    includes(txt, "management port");
    includes(txt, "48211");
    includes(t.doc.querySelector("#ckHits .found").textContent, "5 policies");
    includes(t.text("srcline"), "policies hit-count");
  });

  it("puts logging on the overview and goes there on click", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    includes(t.text("ov"), "Security log mode");
    t.doc.querySelector('.ov-card[data-view="logging"]').click();
    eq(t.$("viewLogging").getAttribute("aria-pressed"), "true");
  });

  it("filters destinations and policies together", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewLogging").click();
    t.$("filter").value = "deny-all";
    t.$("filter").dispatchEvent(new t.window.Event("input"));
    const rows = t.doc.querySelectorAll("#cards tbody tr");
    ok(rows.length >= 1);
    includes(t.text("cards"), "deny-all");
    excludes(t.text("cards"), "allow-web");
  });

  it("narrows to problems", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewLogging").click();
    t.$("problemsOnly").click();
    excludes(t.text("cards"), "siem", "the healthy stream is hidden");
    includes(t.text("cards"), "noc-collector");
  });

  it("exports the logging view", () => {
    const t = load("junos-config-report.html");
    t.$("sampleBtn").click();
    t.$("viewLogging").click();
    const got = [];
    t.window.HTMLAnchorElement.prototype.click = function(){ got.push({ name:this.download, href:this.href }); };
    t.$("csvBtn").click();
    eq(got[0].name, "edge-srx-01-logging.csv");
    const csv = decodeURIComponent(got[0].href.split(",").slice(1).join(","));
    includes(csv.split("\n")[0], '"Session init","Session close","Hits"');
    includes(csv, '"deny-all","deny","no","yes","48211"');

    let md = "";
    Object.defineProperty(t.window.navigator, "clipboard", { configurable:true,
      value:{ writeText: s => { md = s; return Promise.resolve(); } } });
    t.$("mdBtn").click();
    includes(md, "Security log mode: stream");
    includes(md, "| stream | 10.1.0.50:514 (siem) |");
    includes(md, "| 1 | untrust | trust | deny-all | deny | no | yes | 48211 |");
    eq(t.errors, []);
  });

  it("builds a report from logging config alone", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = LOG_SET;
    t.$("parseBtn").click();
    ok(!t.$("msg").classList.contains("on"), "logging config on its own is still a report");
    t.$("viewLogging").click();
    includes(t.text("cards"), "siem");
  });


  it("escapes names taken from the paste", () => {
    const t = load("junos-config-report.html");
    t.$("raw").value = `set security log stream "<img src=x onerror=alert(1)>" host 10.1.0.50`;
    t.$("parseBtn").click();
    t.$("viewLogging").click();
    eq(t.doc.querySelectorAll("#cards img").length, 0);
  });
});

/* ------------------------------------------------------------------ report -- */

Promise.all(pending).then(() => {
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
});
