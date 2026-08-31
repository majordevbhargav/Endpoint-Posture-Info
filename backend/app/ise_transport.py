"""
ise_transport.py - transport-agnostic interface for talking to Cisco ISE.

Two operations only, matching what the platform is actually allowed to do
per the project plan's enforcement model (Section 11): publish a posture
fact, or publish an enforcement action. Neither happens automatically -
callers are the admin-triggered routes in posture_app.py.

Implementations:
    ers_transport.py     - ISE ERS REST API (Context-In API). Default, ships first.
    pxgrid_transport.py   - ISE pxGrid. Stubbed until ISE pxGrid persona /
                             client certs are available (see project plan
                             Section 15, question 3).

Selected via the ENFORCEMENT_TRANSPORT env var: "ers" (default) or "pxgrid".
"""

from __future__ import annotations

import os


class ISETransport:
    """Interface every transport implementation must satisfy."""

    def publish_posture(self, mac: str, status: str, details: str) -> dict:
        """Share a posture fact with ISE. Returns a result dict with at
        least {"ok": bool, "detail": str}."""
        raise NotImplementedError

    def publish_enforcement(self, mac: str, action: str, policy: str | None = None) -> dict:
        """Request an enforcement action (restrict / clear-restriction).
        `action` is "RESTRICT" or "CLEAR_RESTRICTION"."""
        raise NotImplementedError

    def reachable(self) -> bool:
        raise NotImplementedError


def get_transport() -> ISETransport:
    kind = os.getenv("ENFORCEMENT_TRANSPORT", "ers").strip().lower()
    if kind == "pxgrid":
        from pxgrid_transport import PxGridTransport
        return PxGridTransport()
    from ers_transport import ERSTransport
    return ERSTransport()
