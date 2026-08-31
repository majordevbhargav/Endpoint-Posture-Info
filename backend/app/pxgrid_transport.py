"""
pxgrid_transport.py - ISE pxGrid implementation of ISETransport (Section 10 /
Phase 5 of the project plan).

STUB. Requires, before this can be implemented for real:
    - ISE pxGrid persona enabled on the target deployment
    - This platform registered/approved as a pxGrid client with mutual TLS
      certificates (ISE Admin > pxGrid Services)
    - Environment details captured in the project plan, Section 15, question 3

Until those are answered, selecting ENFORCEMENT_TRANSPORT=pxgrid will raise
a clear, explicit error rather than silently falling back to ERS or failing
in a confusing way deep in a request handler.
"""

from __future__ import annotations

from ise_transport import ISETransport


class PxGridNotConfigured(RuntimeError):
    pass


class PxGridTransport(ISETransport):
    def __init__(self):
        raise PxGridNotConfigured(
            "pxGrid transport is not implemented yet (Phase 5 of the project "
            "plan). Set ENFORCEMENT_TRANSPORT=ers until pxGrid persona, "
            "client certificates, and ISE environment details are confirmed."
        )

    def publish_posture(self, mac, status, details):
        raise PxGridNotConfigured()

    def publish_enforcement(self, mac, action, policy=None):
        raise PxGridNotConfigured()

    def reachable(self):
        return False
