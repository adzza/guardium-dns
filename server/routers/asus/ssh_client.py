"""SSH client + DoH IP blocklist for AsusWRT routers.

Used as Stage 3 of the parental-controls escalation:

  Stage 1 (http_client.py)  - block whole MACs at L2 ("Internet Off")
  Stage 2 (http_client.py)  - per-MAC DNS redirect (DNS Director)
  Stage 3 (this module)     - per-MAC iptables drops to known DoH/DoT IPs,
                              defeats Smart-TV apps with embedded DoH
                              clients on a softer profile (e.g. "no
                              YouTube" instead of full Internet Off).

The router runs Dropbear sshd on port 2222 by default; we authenticate
with the same admin password the web UI uses (or a separate SSH password
the user provides). All rules we add carry a comment tagged
``dnsdash:`` so we can identify and remove them on cleanup without
touching anything the user manually configured.

Idempotent: every reconciler tick we recompute the desired set, drop
any of *our* rules that no longer match, and add any missing ones. Safe
to run repeatedly; rule order is preserved.
"""
from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable

import asyncssh


log = logging.getLogger("dns-dashboard.router-ssh")


class AsusSshError(Exception):
    """SSH connection or command-execution failure."""


# -----------------------------------------------------------------------------
# Curated public-DoH/DoT IP list. The goal isn't "block every DNS provider on
# Earth" -- it's "stop Smart-TVs and apps that hardcode the well-known
# `1.1.1.1` / `8.8.8.8` shortcuts". Add more if you discover bypass paths in
# query logs.
# -----------------------------------------------------------------------------
DEFAULT_DOH_IPS: list[str] = [
    # Cloudflare
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3",
    # Google Public DNS
    "8.8.8.8", "8.8.4.4",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # Cisco OpenDNS
    "208.67.222.222", "208.67.220.220",
    "208.67.222.123", "208.67.220.123",
    # AdGuard
    "94.140.14.14", "94.140.15.15",
    "94.140.14.140", "94.140.14.141",
    # CleanBrowsing
    "185.228.168.9", "185.228.169.9",
    # Mullvad
    "194.242.2.2", "194.242.2.3",
    # DNS.SB / DNS.eu
    "185.222.222.222", "45.11.45.11",
    # NextDNS sample anycast endpoints
    "45.90.28.0", "45.90.30.0",
]

IPSET_NAME = "dnsdash_doh"

# We add all our DROP rules to a dedicated chain we own end-to-end. This
# means cleanup is a single ``iptables -F DNSDASH_DOH``; we never touch
# user-managed rules in FORWARD or anywhere else. AsusWRT's stock kernel
# on the RT-BE88U lacks ``xt_comment`` so comment-based tagging isn't an
# option here.
CHAIN_NAME = "DNSDASH_DOH"


@dataclass
class SshConfig:
    host: str
    port: int = 2222
    username: str = "admin"
    password: str = ""
    timeout: float = 10.0
    server_host_key_algs: tuple[str, ...] = (
        "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-256", "ssh-rsa",
    )


@dataclass
class SshResult:
    cmd: str
    rc: int
    stdout: str
    stderr: str


class AsusSshClient:
    """Thin async wrapper around asyncssh with persistent connection."""

    def __init__(self, cfg: SshConfig) -> None:
        self.cfg = cfg
        self._conn: asyncssh.SSHClientConnection | None = None

    async def __aenter__(self) -> "AsusSshClient":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        if self._conn is not None:
            return
        try:
            self._conn = await asyncssh.connect(
                self.cfg.host,
                port=self.cfg.port,
                username=self.cfg.username,
                password=self.cfg.password,
                known_hosts=None,         # router uses dropbear's host key
                client_keys=None,
                server_host_key_algs=list(self.cfg.server_host_key_algs),
                connect_timeout=self.cfg.timeout,
            )
        except (asyncssh.Error, OSError) as exc:
            raise AsusSshError(f"SSH connect failed: {exc}") from exc

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            try:
                await self._conn.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    async def run(self, cmd: str, *, check: bool = False,
                  stdin: str | None = None) -> SshResult:
        if self._conn is None:
            raise AsusSshError("not connected")
        try:
            r = await self._conn.run(cmd, check=False, input=stdin)
        except asyncssh.Error as exc:
            raise AsusSshError(f"SSH run failed: {exc}") from exc
        result = SshResult(
            cmd=cmd,
            rc=int(r.exit_status or 0),
            stdout=(r.stdout or "").strip(),
            stderr=(r.stderr or "").strip(),
        )
        if check and result.rc != 0:
            raise AsusSshError(
                f"command failed (rc={result.rc}): {cmd}\n{result.stderr or result.stdout}"
            )
        return result

    # --------------------------------------------------------------- iptables

    async def has_ipset(self) -> bool:
        r = await self.run("which ipset 2>/dev/null && ipset --version 2>&1 | head -1")
        return r.rc == 0 and "ipset" in r.stdout.lower()

    async def has_iptables_match_set(self) -> bool:
        """Functional probe: actually try to create+use+remove a tiny ipset.

        We can't trust ``lsmod`` (modules may be built into the kernel) or
        ``iptables -m set --help`` (returns generic help on success), so the
        only reliable signal is "does the kernel actually accept it?".
        """
        probe = "_dnsdash_probe"
        try:
            steps = [
                f"ipset create -exist {probe} hash:net family inet",
                f"ipset add -exist {probe} 1.2.3.4",
                f"iptables -I INPUT 1 -m set --match-set {probe} src -j RETURN",
                f"iptables -D INPUT -m set --match-set {probe} src -j RETURN",
                f"ipset destroy {probe}",
            ]
            for cmd in steps:
                r = await self.run(cmd)
                if r.rc != 0:
                    log.debug("xt_set probe failed at: %s -> %s", cmd, r.stderr)
                    return False
            return True
        finally:
            # Best-effort cleanup if we returned False mid-stream.
            await self.run(
                f"iptables -D INPUT -m set --match-set {probe} src -j RETURN 2>/dev/null"
            )
            await self.run(f"ipset destroy {probe} 2>/dev/null")

    async def ensure_ipset(self, ips: Iterable[str], *, name: str = IPSET_NAME) -> None:
        ips_list = sorted({i.strip() for i in ips if i.strip()})
        # Use hash:net so /24 etc. work alongside single IPs.
        await self.run(
            f"ipset create -exist {shlex.quote(name)} hash:net "
            "family inet hashsize 1024 maxelem 256",
            check=True,
        )
        await self.run(f"ipset flush {shlex.quote(name)}", check=True)
        if not ips_list:
            return
        # Feed lines straight to ipset stdin (more reliable than heredocs
        # over an asyncssh channel).
        stdin = "\n".join(f"add {name} {ip}" for ip in ips_list) + "\n"
        r = await self.run("ipset restore -exist", stdin=stdin)
        if r.rc != 0:
            log.warning("ipset restore failed (rc=%d): %s -- falling back to per-IP add",
                        r.rc, r.stderr or r.stdout)
            for ip in ips_list:
                await self.run(f"ipset add -exist {shlex.quote(name)} {shlex.quote(ip)}")

    async def ensure_chain(self, name: str = CHAIN_NAME, *, parent: str = "FORWARD") -> None:
        """Create our chain (idempotent) and ensure FORWARD jumps to it.

        We insert the jump at position 1 so our drops fire before any
        user/firmware rule could ALLOW the same traffic. Idempotent: safe
        to call every reconcile tick.
        """
        # Create the chain if it doesn't exist. ``-N`` returns rc=1 if it
        # exists already, so we ignore failure.
        await self.run(f"iptables -N {shlex.quote(name)} 2>/dev/null")
        # Make sure FORWARD jumps to it exactly once. ``-C`` checks; if it
        # returns nonzero we install the jump.
        check = await self.run(
            f"iptables -C {shlex.quote(parent)} -j {shlex.quote(name)} 2>/dev/null"
        )
        if check.rc != 0:
            r = await self.run(
                f"iptables -I {shlex.quote(parent)} 1 -j {shlex.quote(name)}"
            )
            if r.rc != 0:
                raise AsusSshError(
                    f"failed to install jump from {parent} to {name}: "
                    f"{r.stderr or r.stdout}"
                )

    async def flush_chain(self, name: str = CHAIN_NAME) -> int:
        """Empty our chain. Returns count of rules removed (best effort)."""
        before = await self.run(f"iptables -S {shlex.quote(name)} 2>/dev/null")
        if before.rc != 0:
            return 0  # chain doesn't exist
        prev_rules = sum(1 for ln in before.stdout.splitlines()
                         if ln.startswith("-A "))
        await self.run(f"iptables -F {shlex.quote(name)}")
        return prev_rules

    async def teardown_chain(self, name: str = CHAIN_NAME, *, parent: str = "FORWARD") -> None:
        """Remove the jump from FORWARD and delete the chain entirely."""
        await self.run(
            f"iptables -D {shlex.quote(parent)} -j {shlex.quote(name)} 2>/dev/null"
        )
        await self.run(f"iptables -F {shlex.quote(name)} 2>/dev/null")
        await self.run(f"iptables -X {shlex.quote(name)} 2>/dev/null")

    async def list_chain_rules(self, name: str = CHAIN_NAME) -> list[str]:
        r = await self.run(f"iptables -S {shlex.quote(name)} 2>/dev/null")
        if r.rc != 0:
            return []
        return [ln for ln in r.stdout.splitlines() if ln.startswith("-A ")]

    async def add_doh_drop_rules(
        self,
        macs: list[str],
        *,
        ipset_name: str = IPSET_NAME,
        chain: str = CHAIN_NAME,
    ) -> int:
        added = 0
        for mac in macs:
            mac_q = shlex.quote(mac.upper())
            # 3 rules per MAC: TCP/443 (DoH), UDP/443 (DoH3/QUIC), TCP/853 (DoT).
            for proto, port in (("tcp", 443), ("udp", 443), ("tcp", 853)):
                cmd = (
                    f"iptables -A {shlex.quote(chain)} "
                    f"-m mac --mac-source {mac_q} "
                    f"-m set --match-set {shlex.quote(ipset_name)} dst "
                    f"-p {proto} --dport {port} "
                    f"-j DROP"
                )
                r = await self.run(cmd)
                if r.rc == 0:
                    added += 1
                else:
                    log.warning("iptables -A %s failed for mac=%s proto=%s: %s",
                                chain, mac, proto, r.stderr or r.stdout)
        return added

    async def apply_doh_blocklist(
        self,
        macs: list[str],
        doh_ips: list[str] | None = None,
    ) -> dict[str, Any]:
        """Reconcile the DoH blocklist for the given MACs.

        Strategy:
          1. ensure ipset ``dnsdash_doh`` exists and contains the curated
             list of well-known DoH/DoT endpoints.
          2. ensure our custom chain ``DNSDASH_DOH`` exists and is jumped
             to from FORWARD position 1.
          3. flush our chain (remove all our prior rules).
          4. add 3 fresh DROP rules per managed MAC (TCP/443, UDP/443,
             TCP/853).

        When ``macs`` is empty, we tear the chain down entirely so the
        firewall is back to exactly the user's pre-dashboard state.
        """
        ips = doh_ips if doh_ips is not None else DEFAULT_DOH_IPS

        if not await self.has_ipset():
            raise AsusSshError("router lacks ipset; not supported")
        if not await self.has_iptables_match_set():
            raise AsusSshError("router lacks iptables xt_set match")

        clean_macs = sorted({m.strip().lower() for m in macs if m and ":" in m})

        if not clean_macs:
            # Full tear-down to leave the router exactly as we found it.
            removed = await self.flush_chain()
            await self.teardown_chain()
            await self.run(f"ipset destroy {shlex.quote(IPSET_NAME)} 2>/dev/null")
            return {"macs": [], "removed": removed, "added": 0,
                     "ipsetIps": 0, "chain": CHAIN_NAME, "torn_down": True}

        await self.ensure_ipset(ips)
        await self.ensure_chain()
        removed = await self.flush_chain()
        added = await self.add_doh_drop_rules(clean_macs)
        return {
            "macs": clean_macs,
            "removed": removed,
            "added": added,
            "ipsetIps": len(set(ips)),
            "chain": CHAIN_NAME,
        }

    async def gather_status(self) -> dict[str, Any]:
        """Tiny diagnostic snapshot used by the Settings UI."""
        info: dict[str, Any] = {}
        for label, cmd in (
            ("kernel",   "uname -r"),
            ("model",    "nvram get productid"),
            ("firmware", "nvram get buildno"),
            ("hasIpset", "which ipset >/dev/null && echo yes || echo no"),
            ("ourRules",
             f"iptables -S {CHAIN_NAME} 2>/dev/null | grep -c -- '-A {CHAIN_NAME}' || echo 0"),
            ("ourChainExists",
             f"iptables -S {CHAIN_NAME} >/dev/null 2>&1 && echo yes || echo no"),
        ):
            r = await self.run(cmd)
            info[label] = r.stdout.strip() if r.rc == 0 else None
        return info
