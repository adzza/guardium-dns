<div align="center">

# Guardium DNS

**Parental controls for [Technitium DNS](https://technitium.com/dns/).**

[![Status](https://img.shields.io/badge/status-early%20development-orange)](#status)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)](#requirements)
[![Built on](https://img.shields.io/badge/built%20on-Technitium%20DNS-6366f1)](https://technitium.com/dns/)

A self-hosted dashboard that turns Technitium DNS into a household-grade
parental control system for parents and home-labbers who want real visibility
and real control of the devices on their LAN — including the modern ones that
actively try to bypass your DNS server.

<br/>

**Free, forever. Made by a parent, for parents.**

Guardium DNS is a side project from a tech dad whose day job is in the
networking world. It exists to give families a full-featured, easy-to-use
way to protect their kids from harmful content online and enforce real
screen-time rules — bedtime, school hours, no-YouTube during homework,
total kill-switches when needed — **without** a monthly subscription to a
cloud filtering service that sees every domain your household ever looks
up. Everything runs on your own hardware, on your own network.

</div>

---

## Status

> [!WARNING]
> **Guardium DNS is in very early development.** It is a personal homelab
> project shared publicly so other parents and home-labbers can use it,
> learn from it, and contribute. APIs, schemas, and UI will change without
> notice. There is no upgrade path between versions yet. **Use at your own
> risk on your own network.**

> [!NOTE]
> **Currently in progress:** UniFi API integration so that self-hosted *and*
> cloud-controlled UniFi devices (UDM, UDM Pro, Cloud Gateway, Dream Router,
> UniFi OS Console) can have Guardium DNS protection wired in directly —
> DHCP DNS handoff, per-client DNS override, and DoH IP blocklists. If you
> run UniFi and want to help test, [open an issue](../../issues/new) so I
> can ping you when the first build lands.

---

## Hardware & router compatibility

> [!IMPORTANT]
> **The author has tested Guardium DNS end-to-end on exactly one router: an
> ASUS RT-BE88U on stock firmware.** Everything else is theoretical. Routers
> from the same family (AsusWRT, Asuswrt-Merlin) are *expected* to work
> because they share the underlying NVRAM keys, but this hasn't been
> verified yet — please report back if you try one.

For routers from any other vendor (UniFi, OpenWrt, EdgeOS, MikroTik,
TP-Link, Netgear, ISP-supplied boxes, etc.), the **DNS-only** layer of
Guardium still works fine — that's where most of the value lives. The
optional **router integration stages** (MAC kill switch, DNS Director, DoH
IP blocklist) are vendor-specific and will need a new adapter module per
firmware family.

If you want a vendor adapter and you're comfortable poking at your own
router, [open an issue](../../issues/new) describing the model and
firmware. Adding a new vendor is realistically a **community effort**: the
author needs direct (or remote, shell-access) cooperation from someone
who owns the device, because each firmware exposes a different API surface
(NVRAM keys, HTTP endpoints, SSH commands, iptables modules) and there's
no way to develop or test a vendor adapter blind. PRs and "here's what my
router's admin UI looks like" screenshots are welcome.

---

## Screenshots

The mobile-first **Family view** is what most parents will live in. The
**Techie view** (same data, denser tables, charts) is also available with a
tap.

<table>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/overview.png"><img src="docs/screenshots/overview.png" alt="Family overview" /></a>
      <p align="center"><sub><b>Family overview</b> — devices online, blocked-query counter, "Pause for dinner", people and per-profile device groups (here "No&nbsp;YouTube" is active on three devices, including the household's Google TV).</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/devices-list.png"><img src="docs/screenshots/devices-list.png" alt="Devices needing rules" /></a>
      <p align="center"><sub><b>Devices needing rules</b> — every IP without a person or profile assignment is surfaced for one-tap "Assign". Below, a live feed of the most-blocked domains in the last day.</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/profile-picker.png"><img src="docs/screenshots/profile-picker.png" alt="Profile picker" /></a>
      <p align="center"><sub><b>Profile picker</b> — assign any of the seven built-in profiles (or your own custom ones) to a single device. Each profile maps directly to a group in the Technitium Advanced Blocking app.</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/person-detail.png"><img src="docs/screenshots/person-detail.png" alt="Person detail with schedules and quotas" /></a>
      <p align="center"><sub><b>Person detail</b> — a single household member with all their devices, a base profile, recurring schedules (bedtime, school hours, dinner), and an optional daily quota that auto-cuts the internet when hit.</sub></p>
    </td>
  </tr>
</table>

> Screenshots are from the author's home deployment, taken on iOS Safari
> over Tailscale. If you'd like to contribute screenshots from a different
> network (sensitive labels redacted), open a PR against
> `docs/screenshots/`.

---

## What it does

### For parents

- **Per-device profiles** with sensible defaults: `unrestricted`, `default`,
  `kids`, `no-streaming`, `no-gaming`, `no-youtube`, `internet-off`.
- **Per-person rules** — group devices under a household member ("Hudson",
  "Alex") and apply a single profile across all their devices.
- **Schedules** — bedtime, school hours, "homework mode". A profile change
  can apply on a recurring schedule (e.g. block all streaming Mon–Fri
  17:00–19:00).
- **Quotas** — daily caps per category or per app (e.g. 1 hour of YouTube
  per day, after which the category gets sinkholed).
- **One-click family pause** — kill the internet for everyone except the
  adults' devices, instantly.

### For home-labbers

- **Live visibility** into who's online, what they're querying, what's
  blocked, and at what rate.
- **MAC-anchored device tracking** — profiles follow a device across DHCP IP
  changes automatically.
- **Device fingerprinting** — every device gets a vendor (from MAC OUI) and
  a device-type hint (e.g. "Samsung Smart TV", "Apple device", "NVIDIA
  Shield") inferred from DNS query patterns. Helps you identify the rando
  `192.168.4.140` showing up in your logs.
- **Router integration (optional, three stages)** — push enforcement into
  your ASUS router for devices that ignore or bypass DNS-based blocking.
- **Idempotent reconciler** — every 60 seconds, dashboard state is
  reconciled against Technitium and (if configured) your router. Nothing is
  one-shot; everything self-heals.
- **Zero-Technitium-modification** — Guardium talks to Technitium only over
  its HTTP API. We never patch Technitium's binaries, configs on disk, or
  systemd unit. Technitium upgrades cannot break Guardium, and removing
  Guardium leaves Technitium untouched.
- **One-command updates** — the installer drops a `guardium-update` CLI
  onto the host. The dashboard polls GitHub on a 30-minute cadence and
  surfaces a badge in the nav when a newer commit lands; running the CLI
  pulls, redeploys, restarts the service, and **auto-rolls back** if the
  new build fails its health check.

---

## How it works

### Architecture at a glance

```
                ┌────────────────────────────────────────────────────────┐
                │             Browser (any device on LAN)                │
                └───────────────────────┬────────────────────────────────┘
                                        │  HTTPS/HTTP
                                        ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ Guardium DNS (FastAPI on :8080)                              │
        │                                                              │
        │  ┌─────────────┐  ┌───────────────┐  ┌────────────────┐      │
        │  │ Reconciler  │  │ Override      │  │ Sampler        │      │
        │  │  (60s loop) │  │  engine       │  │ (5min)         │      │
        │  └──────┬──────┘  └───────┬───────┘  └────────┬───────┘      │
        │         └──────────┬──────┴───────────────────┘              │
        │                    ▼                                         │
        │            ┌──────────────┐   ┌──────────────────────┐       │
        │            │ SQLite store │   │ Encrypted vault      │       │
        │            │ (devices,    │   │ (router credentials, │       │
        │            │  schedules,  │   │  Fernet-encrypted)   │       │
        │            │  usage…)     │   └──────────────────────┘       │
        │            └──────────────┘                                  │
        └──────┬─────────────────────┬─────────────────────────┬───────┘
               │ HTTP API            │ HTTP API                │ SSH / HTTP
               ▼                     ▼                         ▼
       ┌───────────────┐    ┌──────────────────┐    ┌─────────────────────┐
       │ Technitium    │    │ LAN gateway      │    │ ASUS router         │
       │ DNS Server    │    │ (PTR / dnsmasq)  │    │ (firewall + NVRAM)  │
       │ :5380         │    │                  │    │                     │
       └───────────────┘    └──────────────────┘    └─────────────────────┘
```

- **Backend**: Python 3.11+ / FastAPI / Uvicorn, single process under
  `dns-dashboard.service`.
- **Frontend**: Tailwind CSS + Alpine.js + Chart.js, no build step (CDN).
- **Storage**: SQLite at `/var/lib/dns-dashboard/dashboard.db`.
- **Port**: `8080` (Technitium itself stays on `5380`).
- **Auth**: reuses Technitium admin credentials. The login form proxies to
  Technitium's `/api/user/login`; the token comes back, gets stored in an
  HTTP-only cookie, and Guardium uses it on every backend call.

### Profiles → Technitium Advanced Blocking groups

Profiles are not invented by Guardium — they map 1:1 onto **groups in the
Technitium [Advanced Blocking](https://github.com/TechnitiumSoftware/DnsServer/blob/master/Apps/AdvancedBlockingApp/README.md) app**.
On every dashboard start, Guardium re-asserts these seven managed groups
in Technitium, populated with the blocklist URLs and domain lists from
`server/profiles.py`:

| Profile | Block list URLs | Explicit domain blocks |
|---|---|---|
| `unrestricted` | — | — |
| `default` | StevenBlack `hosts` (ads + trackers) | DoH bootstrap domains |
| `kids` | StevenBlack + porn-only + social-only + gambling-only + fakenews-only | DoH bootstrap + 12 YouTube domains |
| `no-youtube` | StevenBlack | DoH bootstrap + 12 YouTube domains |
| `no-streaming` | StevenBlack | DoH bootstrap + YouTube + 22 streaming domains (Netflix, Disney+, Hulu, Twitch, Spotify, TikTok, Stan, Binge, Kayo, 9now, 10play, 7plus, iview, SBS) |
| `no-gaming` | StevenBlack | DoH bootstrap + 30 gaming domains (Steam, Epic, Fortnite, Xbox Live, PSN, Nintendo, Roblox, Minecraft, EA, Battle.net, Riot, Ubisoft, Discord) |
| `internet-off` | — | DoH bootstrap + a `.*` regex (matches every query) |

The **"DoH bootstrap"** set is the 25 hostnames clients use to *discover*
encrypted-DNS providers (`dns.google`, `cloudflare-dns.com`,
`mask.icloud.com`, `dns.nextdns.io`, `dns.quad9.net`, `doh.opendns.com`,
`dns.adguard.com`, `doh.mullvad.net`, etc.). Blocking them at the DNS
layer prevents iOS Private Relay, Chrome's secure DNS, Firefox's DoH,
Android Private DNS, and Microsoft's Office private resolver from
*activating* — which forces those clients to fall back to Technitium,
where the rest of the profile takes effect.

Blocks are answered with **`0.0.0.0` / `::`** (a sinkhole) rather than
NXDOMAIN. NXDOMAIN lets DoH clients silently retry a secondary resolver
and lets some smart-TV/IoT devices fall back to hardcoded public DNS;
returning a non-routable IP looks like a successful resolution and keeps
the client stuck on you.

A catch-all `0.0.0.0/0` (and `[::]/0`) is mapped to the `default` group,
so any device you haven't explicitly assigned a profile to still gets
sane ad/tracker blocking out of the box.

> [!IMPORTANT]
> Guardium owns the seven managed group names. If you edit one of these
> groups inside Technitium's UI (add a domain to `kids`, change the
> blocklist URLs on `default`, etc.), your edit **will be overwritten**
> the next time the dashboard restarts. Groups you create in Technitium
> with **any other name** are left completely alone. If you want a
> personalised variant of a managed profile, copy it under a new name in
> Technitium and it will survive every reconcile.

### MAC-anchored device tracking

Technitium identifies devices by IP. That's a problem when your kid's phone
reboots and DHCP hands it a new lease — suddenly the `kids` profile is on
the *old* IP and the phone is unfiltered.

Guardium fixes this by tracking every device by **MAC address**:

1. The reconciler pulls the live client list from the router on every tick
   (`ip ↔ mac`).
2. If a known MAC has moved to a new IP, the device row in SQLite is
   atomically migrated to the new IP, carrying its label, profile,
   schedules, quotas, daily usage, person-membership, and favourite status.
3. Technitium's per-IP `networkGroupMap` is updated in the same pass; stale
   entries for the old IP are removed.

The result: profiles "stick" to devices across reboots and lease churn, no
manual intervention.

### Device fingerprinting

For every device, Guardium derives two hints:

1. **Vendor** — looked up from the MAC OUI against the
   [IEEE OUI registry](https://standards-oui.ieee.org/oui/oui.csv) (cached
   offline on first run, with Wireshark `manuf` mirrors as a fallback).
2. **Device-type hint** — a hand-curated rule set (`server/fingerprint.py`)
   scans the device's recent DNS queries against ~100 known domain
   patterns. Tier-1 specific (`shield.nvidia.com` → "NVIDIA Shield"),
   tier-2 vendor-only (`samsungelectronics.com` → "Samsung device"),
   tier-3 weak hint (`apple.com` → "Apple device").

Both run automatically in the background (≤5 devices/min), and you can
force-refresh a single device with the in-row identify button. Helps
enormously when a device shows up with a randomized MAC and no hostname.

### Defence in depth — the four-layer blocking model

Guardium does its filtering in **four stacked layers**, each one closing a
class of bypass that the layer above can't reach. You can run with just
Layer 0 and most well-behaved devices stay blocked; the router layers
exist for the devices that actively try to escape.

| Layer | Where it runs | Mechanism on the wire | Defeats |
|---|---|---|---|
| **0. DNS sinkhole** | Technitium DNS server (always on) | Returns `0.0.0.0` / `::` (never `NXDOMAIN`) for blocked domains and the 25-hostname DoH-bootstrap set | Cooperative clients; stops iOS Private Relay, Chrome Secure DNS, Firefox DoH, Android Private DNS, and the MS Office private resolver from activating in the first place |
| **1. MAC kill switch** | ASUS router (HTTP / NVRAM) | Built-in MAC filter (`MULTIFILTER_*`) refuses to forward *any* IP packet from listed MACs | A device that ignores every form of DNS entirely |
| **2. DNS Director** | ASUS router (HTTP / NVRAM) | Per-MAC iptables `DNAT` on `PREROUTING` rewrites UDP/53 + TCP/53 destinations to point at Technitium | A device that hard-codes plaintext DNS (e.g. `8.8.8.8:53`) |
| **3. DoH IP blocklist** | ASUS router (SSH / iptables + ipset) | `DROP` outbound TCP/443 (DoH) and TCP/853 (DoT) from listed MACs to a curated set of provider IPs — Google, Cloudflare, Quad9, NextDNS, AdGuard, Mullvad… | A device that hard-codes a DoH or DoT endpoint by **IP** (e.g. Google TVs hitting `8.8.8.8:443` directly) |

A few mechanics worth understanding because they recur in the stage
details below:

- **Why `0.0.0.0`, not `NXDOMAIN`.** Many clients treat `NXDOMAIN` as
  *"this resolver doesn't know"* and silently retry against a hard-coded
  fallback resolver — typically a public one — which would defeat
  every layer above. A `0.0.0.0` reply looks like a successful
  resolution that just happens to go nowhere, so the client stays
  bound to Technitium and the next query also goes through us.
- **Why Layer 3 has to drop the SYN, not RST it.** A TCP RST tells the
  client *"this connection is refused, try another path"*. A silent
  drop just looks like the destination is unreachable; after a
  couple of timeouts most DoH-fallback state machines give up and
  revert to the network's configured DNS — which is Technitium.
- **Layers 1+2 live in NVRAM**, so they survive router reboot on
  their own. Layer 3 (iptables / ipset) is RAM-only on AsusWRT, so
  the reconciler re-asserts the chain on every 60-second tick.
- **Everything Guardium adds to the router is name-scoped** —
  dedicated NVRAM list entries (Layers 1+2) or a dedicated
  `DNSDASH_DOH` iptables chain referencing a `dnsdash_doh` ipset
  (Layer 3). Manual router config is never touched, and disabling a
  stage triggers a clean teardown on the next reconciler tick.

The Layer-0 sinkhole is unconditional and free. Layers 1–3 below are
optional and require router integration.

### Router integration — three stages

DNS-level blocking is great. It is also **trivially bypassed** by any device
that hard-codes its own DNS (lots of smart TVs do) or uses DNS-over-HTTPS
(every modern phone, Chromecast, Google TV, Amazon Echo, etc.). Guardium
includes optional router integration to close those holes.

> [!NOTE]
> Router integration is **optional** but **strongly recommended** for
> households with smart TVs, gaming consoles, or any device you don't fully
> trust. Currently supports **ASUS routers** (RT-BE88U-class hardware
> verified; should work on any AsusWRT/Merlin device with the same NVRAM
> keys).

Router credentials (IP, username, password, optional SSH key) are stored
encrypted at rest using a Fernet key generated on first boot. Everything
the dashboard adds to your router is tagged or kept in a dedicated chain so
it can be cleanly removed without touching the rules you've added by hand.

#### Stage 1 — MAC-based "internet off" (HTTP)

Uses the router's built-in **MAC filter** feature (`MULTIFILTER_*` NVRAM
keys) to block specified MAC addresses at the firewall level. When a
device is on the `internet-off` profile, its MAC is added to the router's
block list; the device cannot send *any* IP traffic, not just DNS.

- **Defeats:** every form of DNS bypass (the device can't route at all).
- **Survives router reboot:** yes (NVRAM-persistent).
- **Requires:** HTTP admin access to the router. SSH not needed.

#### Stage 2 — DNS Director per MAC (HTTP)

Uses **DNS Director** (`dnsfilter_*` NVRAM keys) — ASUS's name for
per-MAC DNS NAT. Mechanically, it installs an iptables `DNAT` rule on
the router's `PREROUTING` chain that says:

> *"If the source MAC is in this list, rewrite the destination of any
> UDP/53 or TCP/53 packet to point at Technitium."*

So a smart TV that hard-codes `8.8.8.8` as its DNS server sends a
query to `8.8.8.8:53`, the router intercepts it on the way out and
rewrites it to `<technitium-ip>:53`. The device never knows — reply
traffic is un-NAT'd on the way back so the source IP looks like
`8.8.8.8`, keeping the client happy — but in reality every query
went through Technitium and obeyed the device's profile.

Devices on any profile other than `unrestricted` get steered into the
dashboard's filter automatically.

This **only catches plaintext DNS**. DoH (TCP/443) and DoT (TCP/853)
travel on different ports and look like ordinary HTTPS to the router;
that's Stage 3's job.

- **Defeats:** hard-coded plain-DNS (UDP/TCP port 53) bypass.
- **Survives router reboot:** yes (NVRAM-persistent).
- **Requires:** HTTP admin access. SSH not needed.

#### Stage 3 — DoH IP blocklist (SSH + iptables/ipset)

This is the one that beat the TCL Google TV.

> #### The Google TV story
>
> Several Google-branded smart TVs (TCL, Sony, Hisense Google TVs;
> Chromecast with Google TV) **silently fall back to DNS-over-HTTPS
> against `dns.google` and `dns64.dns.google`** the moment their
> configured DNS looks unhappy — a single dropped packet, a blocked
> answer, sometimes just elevated latency. Critically, they don't
> resolve `dns.google` to find Google's DoH server: they **hard-code
> the IP** and open TCP/443 straight to `8.8.8.8` / `8.8.4.4`. That
> defeats every DNS-layer defence above, including DoH hostname
> sinkholing.
>
> Stage 3 attacks the problem at the IP layer. The dashboard SSHes
> into the router (Dropbear) and:
>
> 1. creates a kernel `ipset` (`dnsdash_doh`, type `hash:ip`)
>    populated with the IPv4 and IPv6 addresses of known DoH/DoT
>    endpoints — Google, Cloudflare, Quad9, NextDNS, AdGuard,
>    Mullvad, and friends;
> 2. creates a dedicated iptables chain (`DNSDASH_DOH`) hooked from
>    `FORWARD`, containing rules that **silently `DROP`** outbound
>    TCP/443 (DoH) and TCP/853 (DoT) **from listed MACs** to any IP
>    in the set.
>
> Result: the Google TV opens `tcp://8.8.8.8:443`, the SYN reaches
> the router, matches MAC + dest-in-set + dport-443, and is
> **silently dropped — no RST**. The TV's TCP stack sees a timeout,
> not a refusal, so it doesn't try a different DoH path; after a
> couple of timeouts its DoH fallback logic gives up and it reverts
> to plaintext DNS against its configured server, which is
> Technitium. Technitium then enforces the `no-youtube` profile and
> YouTube stays blocked. Mission accomplished.

- **Defeats:** DNS-over-HTTPS bypass to known providers.
- **Survives router reboot:** rules need to be re-applied (the reconciler
  does this on every tick, so it's transparent).
- **Requires:** SSH access to the router with `iptables` + `ipset` + the
  `xt_set` kernel module. The dashboard probes for this on first run and
  reports back if the firmware doesn't have what it needs.

### Walking through it — blocking YouTube on a Google TV

The TCL Google TV in the author's living room is what motivated most
of the router-integration work. Here's exactly what happens, packet
by packet, when it's set to the `no-youtube` profile with all four
layers enabled:

1. **TV asks for `youtube.com` over plaintext DNS** using the resolver
   DHCP handed it — Technitium. Technitium's `no-youtube` group
   contains `youtube.com` and ~12 friends and answers `0.0.0.0`.
   YouTube doesn't load. **Layer 0 wins.**
2. **TV decides Technitium is "broken" and queries `8.8.8.8:53`
   directly**, ignoring DHCP. The router's `PREROUTING` chain sees
   the packet, matches the TV's MAC, and `DNAT`s the destination to
   Technitium. Technitium answers `0.0.0.0` again. **Layer 2 wins.**
   From the TV's logs it looks like Google DNS itself blocked YouTube.
3. **TV gives up on plaintext DNS and falls back to
   `tcp://8.8.8.8:443` (DoH).** The router's `FORWARD` chain jumps
   into `DNSDASH_DOH`, matches MAC + destination IP in
   `dnsdash_doh` + dport 443, and silently drops the SYN. The TV's
   TCP stack times out — no RST, no ICMP-unreachable, just silence.
   **Layer 3 wins.**
4. **TV's DoH fallback logic gives up** after a couple of timeouts
   and reverts to plaintext DNS against its configured resolver,
   which is Technitium. Loop back to step 1. The TV is now stuck on
   Technitium and YouTube stays blocked indefinitely.

If you flip the profile back to `unrestricted`, the same packets
flow but the answers change:

- Layer 0 lets YouTube domains resolve normally.
- Layer 2 still NAT-rewrites port 53 to Technitium, but Technitium
  now answers truthfully.
- Layer 3 still drops TCP/443 to `8.8.8.8`, but the TV no longer
  needs DoH because plaintext DNS is succeeding, so the drop never
  fires.

YouTube comes back **instantly** — no router state changes, no TV
reboot needed. The reconciler's next 60s tick updates the router's
per-MAC steering and the device transitions cleanly.

**Layer 1 (MAC kill switch)** isn't used in this scenario — it's
held in reserve for the `internet-off` profile, where the goal is
*"no traffic at all"* rather than *"all traffic, but YouTube
broken"*. If the same TV gets put on `internet-off`, the router
refuses to forward any packet from its MAC, and steps 1-3 above
never even happen.

---

## What works without router integration

You can run Guardium with **zero router setup** and get a lot of value. The
table below shows what each layer can and can't do.

| Capability | DNS-only | + Stage 1 | + Stage 2 | + Stage 3 |
|---|:---:|:---:|:---:|:---:|
| Ad/tracker blocking on cooperative devices | ✅ | ✅ | ✅ | ✅ |
| Per-profile category blocking (kids, no-streaming, …) | ✅ | ✅ | ✅ | ✅ |
| Schedules, quotas, family pause | ✅ | ✅ | ✅ | ✅ |
| Block `internet-off` device that ignores DHCP DNS | ❌ | ✅ | ✅ | ✅ |
| Block device that hard-codes `8.8.8.8` plain DNS | ❌ | partial¹ | ✅ | ✅ |
| Block device that uses DoH (`dns.google` etc.) | ❌ | ✅² | ❌ | ✅ |
| Block device that uses DoT (port 853) | ❌ | ✅² | ❌ | ✅ |
| Block VPN bypass (Mullvad, NordVPN, …) | ❌ | ✅² | ❌ | partial³ |

¹ Stage 1 turns the device off entirely, so technically yes — but only as
"internet off", not selective.
² Stage 1 just kills all traffic, so it trivially blocks anything.
³ Stage 3 blocks well-known VPN provider IPs but it is a moving target.

**TL;DR**: DNS-only is fine for laptops, phones, Apple TVs, and any device
that respects DHCP. For smart TVs, game consoles, and anything Google-y,
enable Stage 2 and Stage 3.

---

## Requirements

- A Linux server (Debian/Ubuntu tested) with:
  - **Technitium DNS Server** installed and reachable on
    `http://127.0.0.1:5380`, with the **Advanced Blocking** app enabled,
  - Python 3.11+ and `python3-venv`.
- A permanent Technitium API token (the install script will prompt or
  accept one via `DASHBOARD_BOOT_TOKEN`).
- **Optional but recommended:** an ASUS router (AsusWRT or
  Merlin/Asuswrt-Merlin) with admin access. Stage 3 additionally needs SSH
  access and `iptables` + `ipset` (`xt_set`).

---

## Install

There are two pieces to a Guardium DNS deployment:

1. A **Technitium DNS server** somewhere on your LAN (the actual resolver).
2. The **Guardium dashboard** service, which usually lives on the same host
   as Technitium and talks to it over `127.0.0.1:5380`.

You also need a way to make the devices on your network *use* Technitium for
DNS — that's a one-time change on your home router.

### Reference deployment (what the author runs)

This is the exact setup the project is developed and tested on. Mileage
will vary with other distributions, hypervisors, and routers; this is the
known-good path.

- **Hypervisor:** Proxmox VE.
- **Technitium DNS:** Debian 13 LXC container, installed via the brilliant
  [community-scripts.org](https://community-scripts.org/scripts/technitiumdns)
  Proxmox helper script (see Step 1).
- **Guardium dashboard:** installed *inside the same LXC* alongside
  Technitium, by `rsync`-ing this repo and running `deploy/install.sh`.
- **Router:** ASUS RT-BE88U on stock firmware, with LAN DHCP pointing every
  client at the Technitium LXC IP.

If you don't have Proxmox, anything that gives you a Linux host with
network reach to your LAN will do — a Raspberry Pi, a NUC, an Ubuntu VM in
your cloud of choice over a VPN, etc. The Guardium installer assumes a
modern Debian/Ubuntu environment with `apt`.

### Step 1 — Install Technitium DNS

> [!IMPORTANT]
> **Use a fresh Technitium DNS install for Guardium.** Guardium writes its
> own blocking groups, sinkhole rules, app configuration, and Advanced
> Blocking settings into the Technitium server it's pointed at. If you
> bolt it onto an existing Technitium deployment that already has hand-
> tuned groups, custom block lists, or other apps wired up, those changes
> **can conflict with, overwrite, or break** your existing configuration —
> and you may see unexpected resolver behaviour as a result.
>
> The strongly recommended path is to spin up a **new, dedicated Technitium
> LXC / VM / container** just for Guardium. If you absolutely must reuse
> an existing one, back up `/var/lib/technitium-dns-server/` first and be
> prepared to roll back.

If you already have a **dedicated, Guardium-only** Technitium server, skip
to Step 2.

The author's recommended path on Proxmox is the
[community-scripts.org Technitium DNS helper](https://community-scripts.org/scripts/technitiumdns).
On your Proxmox VE node's shell, run:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/technitiumdns.sh)"
```

Accept the defaults (Debian 13, 1 CPU, 512 MB RAM, 2 GB disk) or bump them
if you want bigger query log retention. When it finishes, write down the
LXC's IP address — you'll point your router at it shortly.

> The helper script comes from the community-driven
> [Proxmox VE Scripts](https://community-scripts.org/) project (built in
> memory of [tteck](https://github.com/tteck)). Huge thanks to them.

Verify Technitium is reachable:

```bash
curl -s http://<LXC-IP>:5380/ | head -1
```

You should get an HTML response. If not, check `pct list` on the Proxmox
host and `pct start <id>` if the container isn't running.

### Step 2 — Enable the Advanced Blocking app

Guardium maps profiles 1:1 onto groups inside Technitium's **Advanced
Blocking** app, so the app needs to be installed.

1. Open the Technitium web UI: `http://<LXC-IP>:5380/`.
2. Create your admin user when prompted.
3. Go to **Apps**, click **Browse Store**, find **Advanced Blocking**, and
   click **Install**.
4. Once installed, click its **Config** button to open it at least once —
   this creates the empty `groups` / `networkGroupMap` structures that
   Guardium will populate on first launch.

### Step 3 — Get a Technitium permanent API token

Guardium uses a permanent service token for the one-time bootstrap (after
that, the UI uses your regular Technitium login credentials over an
HttpOnly cookie).

In the Technitium UI:

1. Click your username (top-right) → **Create API Token**.
2. Name it something obvious like `guardium-bootstrap`.
3. Copy the token — it is shown exactly once.

### Step 4 — Install Guardium DNS

From a workstation that can SSH to your Technitium host (in the reference
setup, the Proxmox LXC):

```bash
git clone https://github.com/adzza/guardium-dns.git
cd guardium-dns
BOOT_TOKEN="<paste-the-token-from-step-3>" ./deploy.sh root@<LXC-IP>
```

`deploy.sh` rsyncs the project to `/opt/dns-dashboard/` on the remote and
runs `deploy/install.sh`, which:

1. installs Python + venv tooling if missing,
2. creates a dedicated `dns-dashboard` system user,
3. owns `/opt/dns-dashboard` and `/var/lib/dns-dashboard`,
4. builds a venv and installs Python deps,
5. writes `/etc/dns-dashboard.env` (only on first install, including your
   bootstrap token),
6. installs and starts the `dns-dashboard.service` systemd unit.

When it finishes you'll see:

```
==> done. Dashboard URL:  http://<LXC-IP>:8080/
```

Open that URL, sign in with the same admin user you created in Technitium,
and you're in.

#### What the install does to Technitium

The first time the dashboard starts with a valid service token, it
**writes a complete Advanced Blocking app config to Technitium** —
nothing in the Technitium UI needs to be touched by hand. Specifically:

- Creates (or overwrites) the seven managed groups: `unrestricted`,
  `default`, `kids`, `no-youtube`, `no-streaming`, `no-gaming`,
  `internet-off`. Each group is populated with the appropriate
  StevenBlack blocklist URLs and the curated domain lists from
  `server/profiles.py`.
- Maps `0.0.0.0/0` and `[::]/0` to the `default` group so every device
  on your LAN gets ad/tracker blocking by default, even before you've
  assigned anything explicitly.
- Sets `enableBlocking=true`, `blockingAnswerTtl=30s`, and
  `blockListUrlUpdateIntervalHours=24` (Technitium re-downloads the
  StevenBlack feeds on its own daily schedule).
- Sets the sinkhole address to `0.0.0.0`/`::` rather than NXDOMAIN, to
  defeat DoH-fallback and IoT NXDOMAIN-fallback bypass tricks.
- Auto-installs the **Query Logs (Sqlite)** Technitium app if it isn't
  already present, so the dashboard's per-device query history works
  out of the box.

This same routine re-runs on every dashboard restart, which is what
keeps managed groups consistent (and what makes manual UI edits to those
seven groups not stick — see the warning in *Profiles → Technitium
Advanced Blocking groups* above).

Block-list URLs are *registered* by Guardium; the actual hosts files are
fetched by Technitium itself on its 24-hour schedule. Right after the
install the URLs are wired up but the file contents may not be cached
yet. If you want the lists active immediately, open the Advanced
Blocking app in Technitium and click **Update Now**, or wait up to a
day.

#### Manual install (no rsync)

If you'd rather not push from a workstation:

```bash
sudo git clone https://github.com/adzza/guardium-dns.git /opt/dns-dashboard
sudo DASHBOARD_BOOT_TOKEN=<token> bash /opt/dns-dashboard/deploy/install.sh
```

### Step 5 — Point your router's DHCP at Technitium

Until your router hands out the Technitium IP as the network's DNS, nothing
on your LAN is actually using it.

**On ASUS routers (AsusWRT or Merlin):**

1. Sign in to your router's admin UI (usually `http://router.asus.com/` or
   `http://192.168.1.1/`).
2. Go to **LAN** → **DHCP Server**.
3. Set **DNS Server 1** to your Technitium LXC's IP.
4. Leave **DNS Server 2** **blank** if you want hard guarantees that every
   client uses Technitium. If you set a public fallback like `1.1.1.1`,
   clients are free to pick that one and all your filtering goes out the
   window.
5. Set **Advertise router's IP in addition to user-specified DNS** to
   **No**.
6. Click **Apply**.
7. Reboot any device on your LAN (or wait for its DHCP lease to renew) so
   it picks up the new DNS setting.

**On other routers:** the exact menu name varies, but you're looking for
the DHCP server's DNS option — sometimes called "Custom DNS", "DNS Server
override", or just "DNS Servers". The principle is identical: primary =
your Technitium IP, secondary = empty (or another internal resolver, but
never a public one if you want enforcement).

### Step 6 (optional) — Enable router integration

If you're on an ASUS router and have devices that bypass DNS (smart TVs,
Google TVs, consoles), open the dashboard's **Settings → Router** page and
fill in:

- Router IP, username, password.
- (Optional) SSH credentials for Stage 3 (DoH IP blocklist).

Click **Test connection**, then toggle the stages you want and **Apply**.
The reconciler will push the rules to the router on the next 60-second
tick and self-heal them on every tick after that. Toggling a stage off
triggers a clean teardown of all rules the dashboard added — your manual
router config is never touched.

---

## Updating

Guardium is moving fast. The intended update workflow is intentionally
boring: you don't reinstall, you don't `git pull` by hand, you don't run
`pip install -r requirements.txt` yourself. There's a single command on
the host, and the dashboard tells you when to run it.

### How you find out an update exists

The version of Guardium currently installed is shown as a **pill in the
top-right of the navigation bar** (e.g. `v0.1.0` or a short Git SHA like
`3ba53fa`). The backend polls GitHub for the latest commit on your
configured channel every ~30 minutes and caches the result; if the
remote is ahead of you, the pill flips amber and grows a small ⬆ arrow
badge.

Click the pill at any time to open the **update details modal**. It
shows:

- What you have installed (tag / SHA / commit message / commit date).
- What's on the configured channel (`main` by default), with a
  **"See what changed →"** link straight to the GitHub compare view.
- The two commands you'd use to update (copyable, with one-click copy):
  one for the Guardium host itself, one to run from your workstation
  over SSH.
- A **Check now** button that forces an immediate GitHub poll.
- A **Snooze** button that suppresses the badge until a *newer* commit
  lands (the pill itself stays available so you can always reopen the
  modal).

No data leaves your network at any point other than authenticated
GitHub API calls to `api.github.com/repos/<owner>/<repo>/commits/...`.

### Running the update — `guardium-update`

The installer drops a wrapper script at `/usr/local/bin/guardium-update`.
On the Guardium host:

```bash
sudo guardium-update
```

Or from your workstation, without logging in:

```bash
ssh root@<your-guardium-host> 'guardium-update'
```

The script:

1. Snapshots the currently installed commit (for rollback).
2. `git fetch && git checkout` of the configured `UPDATE_CHANNEL`
   (defaults to `main`) — if the install directory isn't already a git
   checkout, the script bootstraps one in place from `GITHUB_REPO`.
3. Re-runs `deploy/install.sh` to pick up any new dependencies, service
   file changes, or CLI script updates.
4. Restarts `dns-dashboard.service` and performs an HTTP health check
   on `127.0.0.1:8080`.
5. **On failure**, automatically checks out the previous commit, reruns
   the installer, and restarts the service — so a bad commit doesn't
   leave you with a dead dashboard.
6. Stamps `/var/lib/dns-dashboard/version.json` with the new commit
   metadata so the UI immediately reflects the new version.

Typical run is 10–20 seconds. You can re-run it any time — it's
idempotent.

### Following a feature branch

By default Guardium tracks `main`. If you want to ride a feature branch
(for example, to test the in-progress UniFi integration), set
`UPDATE_CHANNEL` in `/etc/dns-dashboard.env` and restart the service:

```bash
sudo sed -i 's/^UPDATE_CHANNEL=.*/UPDATE_CHANNEL=feat\/unifi-integration/' /etc/dns-dashboard.env
sudo systemctl restart dns-dashboard
sudo guardium-update
```

The next poller tick will compare your installed commit against the
tip of that branch, and the badge / modal will reflect it.

To go back to stable, set `UPDATE_CHANNEL=main`, restart, and run
`guardium-update` again.

### What does *not* auto-update

- **Block-list contents.** StevenBlack and friends are fetched by
  Technitium on its own daily schedule, not by Guardium. Hit **Update
  Now** in the Advanced Blocking app config if you want them refreshed
  immediately.
- **Database schema.** Major schema changes between commits may still
  require deleting `/var/lib/dns-dashboard/dashboard.db` and starting
  fresh. The plan is to add real migrations once the schema stabilises;
  for now, see [`CHANGELOG.md`](CHANGELOG.md) for any breaking
  notes per release.
- **Technitium itself.** Guardium never touches the Technitium service
  unit, binaries, or version. Upgrade Technitium with its own
  installer (or the community-scripts helper, on Proxmox).

---

## Configuration

Everything tunable lives in `/etc/dns-dashboard.env` (read at service
start). Defaults are picked for a single-host deployment alongside
Technitium.

| Variable | Default | Purpose |
|---|---|---|
| `TECHNITIUM_URL` | `http://127.0.0.1:5380` | Technitium HTTP API base URL. |
| `TECHNITIUM_SERVICE_TOKEN` | *(empty)* | Permanent service token for boot-time setup (one-time; UI logins take over afterwards). |
| `DASHBOARD_HOST` | `0.0.0.0` | Bind address. |
| `DASHBOARD_PORT` | `8080` | Listen port. |
| `DASHBOARD_DATA_DIR` | `/var/lib/dns-dashboard` | SQLite + Fernet key location. |
| `DASHBOARD_WEB_DIR` | `/opt/dns-dashboard/web` | Static asset directory. |
| `LAN_DNS_RESOLVERS` | *(auto)* | Override LAN gateway used for PTR lookups (defaults to system default route). |
| `GITHUB_REPO` | `adzza/guardium-dns` | Source repo the update CLI and version poller talk to. |
| `UPDATE_CHANNEL` | `main` | Branch (or tag) the dashboard tracks for update notifications and `guardium-update` pulls. Set to e.g. `feat/unifi-integration` to follow a feature branch. |

Router credentials are **not** stored in the env file; they go through the
**Settings → Router** UI and are encrypted at rest with a Fernet key
generated on first boot at `/var/lib/dns-dashboard/secret.key`.

---

## Security model

- **Authentication.** Guardium has no user database of its own. The login
  form forwards your credentials to Technitium's `/api/user/login`. The
  returned token is stored in a `HttpOnly`, `SameSite=Lax` cookie.
- **At-rest secrets.** Router passwords (and any other future secrets) are
  encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key held in
  mode-0600 `/var/lib/dns-dashboard/secret.key`. Plain text never lives in
  the database, in logs, or on the wire to the browser.
- **In-transit.** Guardium currently listens on plain HTTP on `:8080`.
  Put it behind a reverse proxy (Caddy/Traefik/nginx) with TLS if you
  expose it beyond your LAN. There is no plan to bundle TLS termination.
- **No outbound calls** other than:
  - the local Technitium API,
  - the configured LAN gateway (PTR lookups),
  - your router (HTTP/SSH, only if configured),
  - a one-time IEEE/Wireshark OUI download cached to disk.
- **Router rules are tagged.** Everything we add to the router lives in
  named NVRAM list entries (Stages 1–2) or a dedicated iptables chain
  (`DNSDASH_DOH`, Stage 3). Disabling a stage in the UI triggers an
  automatic teardown on the next reconciler tick. Your manual router
  rules are never touched.

---

## Limitations and known issues

- **Single router vendor.** Only ASUS is implemented today. Adding
  OpenWrt/EdgeOS/UniFi is on the roadmap; PRs welcome.
- **DoH/DoT cellular bypass.** Stage 3 blocks DoH/DoT at the *home
  router*. A phone on cellular obviously isn't on your router and
  cannot be filtered. There is no software fix for this; it's a property
  of the device leaving your network.
- **DNS-over-HTTPS rotation.** Stage 3 ships a curated DoH IP list. New
  providers and new IP ranges appear constantly. The list is updated by
  hand for now.
- **No HA/clustering.** Single process, single SQLite file, single host.
  This is a household tool, not a service.
- **No automated database migrations** yet. `guardium-update` handles
  code, deps, and service-restart with auto-rollback, but schema
  changes between commits may still require deleting `dashboard.db`
  manually. Check [`CHANGELOG.md`](CHANGELOG.md) before pulling a
  major version. Backups are your problem.
- **Per-IP, not per-user.** Two people sharing a laptop share a profile.
  "People" grouping helps but it's still device-scoped underneath.
- **TLS termination not bundled.** Put it behind a reverse proxy if you
  care.

---

## Project layout

```
guardium-dns/
├── server/
│   ├── app.py            FastAPI app + HTTP API
│   ├── technitium.py     Async Technitium API client
│   ├── profiles.py       Built-in profile definitions
│   ├── overrides.py      Effective-profile resolver (schedules + quotas)
│   ├── reconciler.py     60s reconciliation loop
│   ├── sampler.py        5min activity sampler (active-minutes per device)
│   ├── hostnames.py      LAN gateway PTR resolver
│   ├── apps.py           App/category usage rollups
│   ├── routers/          Vendor-agnostic router adapters
│   │   ├── base.py       RouterAdapter contract + Capabilities
│   │   ├── registry.py   Vendor selection factory
│   │   └── asus/         AsusWRT adapter (HTTP for Stages 1+2, SSH for Stage 3)
│   ├── oui.py            IEEE OUI vendor lookup
│   ├── fingerprint.py    DNS-query-pattern device-type rules
│   ├── store.py          SQLite store
│   ├── vault.py          Fernet-encrypted secrets store
│   ├── version.py        Installed-version detection + GitHub update poller
│   └── requirements.txt
├── web/
│   ├── index.html        Dashboard UI (Alpine.js SPA)
│   ├── login.html        Login screen
│   ├── app.js            Frontend logic
│   ├── styles.css        Custom CSS
│   └── favicon.svg       Shield icon
├── deploy/
│   ├── dns-dashboard.service
│   ├── install.sh
│   ├── guardium-update.sh   Installed to /usr/local/bin/guardium-update
│   └── setup-reverse-forwarder.sh
├── scripts/
│   ├── identify_all_devices.py
│   └── live_test_mac_anchored.py
├── tests/
│   └── test_mac_anchored.py
├── deploy.sh             Push to remote + run install.sh
├── VERSION               Tracked SemVer (paired with git SHA at runtime)
├── CHANGELOG.md          Per-release notes
├── LICENSE               MIT
└── README.md
```

---

## Roadmap

- [ ] OpenWrt and UniFi router adapters
- [ ] Schedule editor UI (currently API/DB only)
- [ ] Per-app quotas with rich usage charts
- [ ] Mobile-first device list with swipe actions
- [ ] Automatic DoH IP list updates (live feed)
- [ ] Backup/export and schema-migration tooling
- [ ] Optional Prometheus metrics endpoint
- [ ] Docker image
- [ ] Multi-user accounts (separate from Technitium)

If you want a feature, [open an issue](../../issues/new) describing your
use case.

---

## Contributing

This is a one-person hobby project at the moment, but contributions are
welcome — especially:

- **Router adapters** for non-ASUS firmware,
- **Fingerprinting rules** for devices you've identified on your own
  network,
- **Bug reports** with reproduction steps, environment details, and
  reconciler logs (`journalctl -u dns-dashboard -n 200`).

For non-trivial changes, please open an issue first so we can talk about
the approach before you spend time on a PR.

---

## Acknowledgements

- [Technitium DNS Server](https://technitium.com/dns/) — the brilliant
  open-source recursive DNS server this whole project is built around.
  Huge thanks to [@ShreyasZare](https://github.com/ShreyasZare).
- [Proxmox VE Helper Scripts](https://community-scripts.org/) — the
  community-driven script collection (built in memory of
  [tteck](https://github.com/tteck)) that makes spinning up a Technitium
  LXC on Proxmox a one-liner. The reference deployment in this README
  uses their
  [Technitium DNS script](https://community-scripts.org/scripts/technitiumdns).
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — the
  ad/tracker blocklist that powers the `default` profile.
- [Wireshark `manuf`](https://www.wireshark.org/) — fallback OUI database
  when the IEEE direct download is blocked.
- The countless homelab forum threads documenting AsusWRT NVRAM keys.

---

## License

[MIT](LICENSE). Do whatever you want, just don't blame me if it doesn't
work.

> **Disclaimer:** Guardium DNS is not affiliated with, endorsed by, or
> sponsored by Technitium, ASUS, or any other company referenced here.
> "Technitium" and "ASUS" are trademarks of their respective owners.
