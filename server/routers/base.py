"""Vendor-agnostic router adapter contract.

The reconciler talks to exactly one of these per tick. Adapters are
async context managers; entering opens any underlying network sessions
(HTTP, SSH, websocket, ...) and exiting closes them.

Each adapter owns its own persistence: the "previously managed" lists
for each stage are stored under vendor-namespaced setting keys
(``router.{vendor}.managed_kill_macs`` etc.) so adapters can be swapped
without one vendor's bookkeeping leaking into the other.

The reconciler is responsible *only* for computing the desired MAC set
per stage. The adapter decides whether the stage is currently enabled
(by reading its own user-facing toggle settings), and either pushes the
state to the device or tears down whatever it pushed last time.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Capabilities:
    """Static, per-vendor capability flags.

    The Settings UI uses these to enable/disable per-stage toggles, so
    users only see toggles their hardware can actually enforce.
    """

    supports_kill_switch:  bool
    supports_dns_director: bool
    supports_doh_blocking: bool
    needs_ssh_for_doh:     bool = False


@dataclass
class RouterClient:
    """A single client device as the router sees it.

    ``mac`` is required (lowercase, colon-separated). ``ip`` and ``name``
    are best-effort -- some routers don't expose hostnames for every
    device.
    """

    mac: str
    ip: str | None = None
    name: str | None = None
    online: bool = True
    raw: dict[str, Any] = field(default_factory=dict)


class RouterAdapter(abc.ABC):
    """Abstract router adapter.

    Subclasses MUST set :attr:`vendor` and :attr:`capabilities` as class
    attributes, implement the async context manager protocol, and
    implement :meth:`list_clients` plus the three ``apply_*`` methods.
    Adapters for vendors that don't support a given stage should still
    implement the method as a no-op that returns
    ``{"enabled": False, "supported": False}``.
    """

    vendor: str = "abstract"
    capabilities: Capabilities = Capabilities(False, False, False)

    @abc.abstractmethod
    async def __aenter__(self) -> "RouterAdapter":
        """Open any persistent sessions (HTTP login, controller cookie,
        etc.) the adapter needs for the rest of the tick.
        """

    @abc.abstractmethod
    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Close any sessions opened by :meth:`__aenter__`."""

    @abc.abstractmethod
    async def list_clients(self) -> list[RouterClient]:
        """Return every client the router currently knows about.

        Used by the reconciler for:
        - building the live IP<->MAC map
        - the Settings page "router clients" preview
        - MAC-anchored device tracking across DHCP changes
        """

    @abc.abstractmethod
    async def apply_kill_switch(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        """Stage 1: enforce 'Internet Off' for every MAC in ``desired_macs``.

        The adapter MUST be idempotent: passing the same set on repeated
        ticks should be a no-op. Passing an empty set MUST tear down
        whatever the adapter pushed previously, leaving any rules the
        user added by hand in the router UI alone.

        Returns a vendor-agnostic dict. Common keys:
            ``enabled``  : whether the stage is on for this vendor
            ``blocked``  : the set of MACs we believe are now blocked
            ``changed``  : True if this call modified router state
            ``error``    : human-readable failure description (optional)
            ``preservedUserRules``: hand-added entries we left alone
        """

    @abc.abstractmethod
    async def apply_dns_director(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        """Stage 2: per-MAC DNS redirection.

        ``desired_macs`` is every MAC whose effective profile needs the
        router to enforce DNS (i.e. anything on a managed profile other
        than ``unrestricted`` or ``internet-off``).

        Adapters that don't support this stage should return
        ``{"enabled": False, "supported": False}``. The reconciler will
        still call the method; vendors with no support just no-op.
        """

    @abc.abstractmethod
    async def apply_doh_block(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        """Stage 3: drop traffic from each MAC to public DoH/DoT endpoints.

        Same idempotency contract as :meth:`apply_kill_switch`.
        """


class RouterAdapterError(Exception):
    """Raised by adapter helpers when an irrecoverable error occurs.

    Adapter ``apply_*`` methods MUST NOT propagate vendor-specific
    exceptions to the reconciler -- they catch them and return an error
    dict instead. This type exists for the rare adapter helpers that
    really do need to signal a hard failure (e.g. ``test_connection``).
    """
