"""
ers_transport.py - ISE ERS REST (Context-In API) implementation of
ISETransport. This is a thin wrapper around the same ISEClient logic that
already existed in posture_app.py (write_posture / enforce_attribute /
enforce_anc), unchanged in behavior, just re-homed behind the transport
interface so posture_app.py's new share/restrict routes don't need to know
which transport is active.
"""

from __future__ import annotations

import os
import time
from xml.etree import ElementTree

import requests
import urllib3
from requests.auth import HTTPBasicAuth

from ise_transport import ISETransport

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ISE_HOST = os.getenv("ISE_HOST", "").rstrip("/")
ISE_USER = os.getenv("ISE_USER", "")
ISE_PASS = os.getenv("ISE_PASS", "")
VERIFY_TLS = os.getenv("ISE_VERIFY_TLS", "false").lower() == "true"
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "attribute").lower()

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

STATUS_MAP = {"COMPLIANT": "Compliant", "NON-COMPLIANT": "NonCompliant"}


class ERSTransport(ISETransport):
    def __init__(self):
        self.auth = HTTPBasicAuth(ISE_USER, ISE_PASS)

    def _request(self, method, path, **kwargs):
        kwargs.setdefault("auth", self.auth)
        kwargs.setdefault("headers", HEADERS)
        kwargs.setdefault("verify", VERIFY_TLS)
        kwargs.setdefault("timeout", 15)
        response = requests.request(method, f"{ISE_HOST}{path}", **kwargs)
        response.raise_for_status()
        return response.json() if response.text.strip() else {}

    def reachable(self) -> bool:
        try:
            response = requests.get(
                f"{ISE_HOST}/ers/config/endpoint?filter=mac.EQ.00:00:00:00:00:00&size=1",
                auth=self.auth, headers=HEADERS, verify=VERIFY_TLS, timeout=5,
            )
            return response.status_code < 500
        except requests.RequestException:
            return False

    def _endpoint_id(self, mac: str):
        data = self._request("GET", f"/ers/config/endpoint?filter=mac.EQ.{mac}")
        resources = data.get("SearchResult", {}).get("resources", [])
        return resources[0].get("id") if resources else None

    def _session_detail(self, mac: str):
        url = f"{ISE_HOST}/admin/API/mnt/Session/MACAddress/{mac}"
        try:
            response = requests.get(url, auth=self.auth, verify=VERIFY_TLS, timeout=15)
            if response.status_code >= 400 or not response.text.strip():
                return None
            root = ElementTree.fromstring(response.text)
            fields = {}
            for elem in root.iter():
                if len(elem) == 0 and elem.text and elem.text.strip():
                    fields[elem.tag.split("}")[-1]] = elem.text.strip()
            return fields or None
        except (requests.RequestException, ElementTree.ParseError):
            return None

    # -- publish_posture: same operation as the old write_posture() --------

    def publish_posture(self, mac: str, status: str, details: str) -> dict:
        ise_status = STATUS_MAP.get(status, status)
        attrs = {
            "ExternalComplianceStatus": ise_status,
            "PostureLastChecked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "PostureFailedChecks": details or "none",
        }
        body = {"ERSEndPoint": {"mac": mac, "customAttributes": {"customAttributes": attrs}}}
        try:
            endpoint_id = self._endpoint_id(mac)
            if endpoint_id:
                body["ERSEndPoint"]["id"] = endpoint_id
                self._request("PUT", f"/ers/config/endpoint/{endpoint_id}", json=body)
            else:
                self._request("POST", "/ers/config/endpoint", json=body)
            return {"ok": True, "detail": f"Posture shared with ISE as {ise_status}."}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}

    # -- publish_enforcement: same operation as enforce_attribute/enforce_anc --

    def _anc(self, mac: str, policy: str | None):
        path = "/ers/config/ancendpoint/clear" if policy is None else "/ers/config/ancendpoint/apply"
        data = [{"name": "macAddress", "value": mac}]
        if policy:
            data.append({"name": "policyName", "value": policy})
        return self._request("POST", path, json={"OperationAdditionalData": {"additionalData": data}})

    def publish_enforcement(self, mac: str, action: str, policy: str | None = None) -> dict:
        restrict = action == "RESTRICT"
        try:
            if ENFORCEMENT_MODE == "anc":
                self._anc(mac, (policy or "Quarantine") if restrict else None)
                time.sleep(3)
                return {
                    "ok": True,
                    "detail": "ANC_APPLIED" if restrict else "ANC_CLEARED",
                    "session_fields": self._session_detail(mac) or {},
                }

            session = self._session_detail(mac)
            if not session:
                return {"ok": False, "detail": "NO_ACTIVE_SESSION - facts stored, will apply on next connect"}
            psn = session.get("acs_server") or session.get("server")
            if not psn:
                return {"ok": False, "detail": "SESSION_FOUND_BUT_NO_PSN - cannot trigger CoA, check manually"}

            response = requests.get(
                f"{ISE_HOST}/admin/API/mnt/CoA/Reauth/{psn}/{mac}/1",
                auth=self.auth, verify=VERIFY_TLS, timeout=15,
            )
            response.raise_for_status()
            fired = "<results>true</results>" in response.text
            time.sleep(3)
            return {
                "ok": fired,
                "detail": "REAUTH_APPLIED" if fired else "CoA call returned no confirmation",
                "session_fields": self._session_detail(mac) or {},
            }
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}
