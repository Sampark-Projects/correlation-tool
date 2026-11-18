import html
import json
import logging
import os
import queue
import threading
import time

import requests

from keep.api.core.config import config
from keep.api.models.incident import IncidentDto

# Sampark ITSM integration - every incident Keep creates (correlation rule, topology or
# manual) is opened as an ITSM ticket, with the incident UUID as the referenceId.
# Single alerts are not sent. Tickets are sent from a background thread and every error
# is logged and swallowed, so incident processing works exactly the same when the ITSM
# is down or not configured.

logger = logging.getLogger(__name__)

ITSM_INTEGRATION_ENABLED = str(
    config("ITSM_INTEGRATION_ENABLED", default="true")
).lower() in ("true", "1")
ITSM_LOGIN_URL = config(
    "ITSM_LOGIN_URL",
    default="https://itsmqa.samparkme.com/gateway/user-management/api/v1/login",
)
ITSM_TICKET_URL = config(
    "ITSM_TICKET_URL",
    default="https://itsmqa.samparkme.com/gateway/secure/ticket-management/api/create/ticket",
)
ITSM_LOGIN_EMAIL = config("ITSM_LOGIN_EMAIL", default=None)
ITSM_LOGIN_PASSWORD = config("ITSM_LOGIN_PASSWORD", default=None)
ITSM_DEVICE_ID = config("ITSM_DEVICE_ID", default="123456")
ITSM_FORM_ID = config("ITSM_FORM_ID", default="f1e361d5-3b5e-403e-8874-e969a6a24ab0")
ITSM_CATEGORY_ID = config("ITSM_CATEGORY_ID", default="OR000500031")
ITSM_SUB_CATEGORY_ID = config("ITSM_SUB_CATEGORY_ID", default="OR000500031118")
ITSM_DEFAULT_SEVERITY_ID = config("ITSM_DEFAULT_SEVERITY_ID", default="SEV-4")
# contact on the ticket, defaults to the logged in ITSM user
ITSM_TICKET_EMAIL = config("ITSM_TICKET_EMAIL", default=None)
ITSM_TICKET_MOBILE = config("ITSM_TICKET_MOBILE", default=None)
# Keep UI base url (e.g. https://alerts.samparkme.com), used to link the incident in the ticket
ITSM_KEEP_UI_URL = config("ITSM_KEEP_UI_URL", default=None)
try:
    ITSM_TIMEOUT = float(config("ITSM_TIMEOUT", default=15))
except ValueError:
    ITSM_TIMEOUT = 15.0

DEFAULT_SEVERITY_MAP = {
    "critical": "SEV-1",
    "high": "SEV-2",
    "warning": "SEV-3",
    "info": "SEV-4",
    "low": "SEV-4",
}
# the fields the ticket API expects in the metaData header (taken from the login userDetails)
METADATA_FIELDS = [
    "firstName",
    "lastName",
    "roleName",
    "customerId",
    "personId",
    "deviceId",
    "profileImage",
    "email",
    "mobileNo",
    "dob",
    "doj",
    "address",
    "state",
    "city",
    "orgName",
]
TICKET_SOURCE = "correlation tool"
QUEUE_SIZE = 1000
LOGIN_RETRY_INTERVAL_SECONDS = 60
MAX_TITLE_LENGTH = 250
MAX_DESCRIPTION_LENGTH = 4000


def _load_severity_map() -> dict:
    raw = config("ITSM_SEVERITY_MAP", default=None)
    if raw:
        try:
            return {str(key).lower(): value for key, value in json.loads(raw).items()}
        except Exception:
            logger.warning("Invalid ITSM_SEVERITY_MAP, using the default severity map")
    return dict(DEFAULT_SEVERITY_MAP)


ITSM_SEVERITY_MAP = _load_severity_map()


def _json(response: requests.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _is_unauthorized(response: requests.Response) -> bool:
    return response.status_code in (401, 403) or str(
        _json(response).get("statusCode")
    ) in ("401", "403")


class _ItsmClient:
    """Used only by the worker thread, so no locking is needed."""

    def __init__(self):
        self._token = None
        self._user = {}
        self._login_failed_at = None

    def _login(self) -> bool:
        # don't hammer the login API when the credentials are wrong or it is down
        if (
            self._login_failed_at is not None
            and time.monotonic() - self._login_failed_at < LOGIN_RETRY_INTERVAL_SECONDS
        ):
            return False

        self._token = None
        try:
            response = requests.post(
                ITSM_LOGIN_URL,
                headers={"DeviceId": ITSM_DEVICE_ID},
                json={
                    "request": {
                        "requestData": {
                            "email": ITSM_LOGIN_EMAIL,
                            "password": ITSM_LOGIN_PASSWORD,
                        }
                    }
                },
                timeout=ITSM_TIMEOUT,
            )
        except Exception:
            logger.exception("Failed to login to ITSM")
            self._login_failed_at = time.monotonic()
            return False

        body = _json(response)
        login = body.get("responseObject")
        token = login.get("token") if isinstance(login, dict) else None
        if not response.ok or not token:
            logger.error(
                "ITSM login was rejected",
                extra={
                    "status_code": response.status_code,
                    "itsm_message": body.get("message"),
                },
            )
            self._login_failed_at = time.monotonic()
            return False

        self._token = token
        self._user = login.get("userDetails") or {}
        self._login_failed_at = None
        logger.info("Logged in to ITSM")
        return True

    def _post_ticket(self, ticket: dict) -> requests.Response:
        metadata = {field: self._user.get(field) for field in METADATA_FIELDS}
        metadata["deviceId"] = ITSM_DEVICE_ID
        ticket = dict(
            ticket,
            email=ITSM_TICKET_EMAIL or self._user.get("email"),
            mobileNo=ITSM_TICKET_MOBILE or self._user.get("mobileNo"),
        )
        return requests.post(
            ITSM_TICKET_URL,
            headers={
                "metaData": json.dumps(metadata, separators=(",", ":")),
                "Authorization": self._token,
                "deviceid": ITSM_DEVICE_ID,
            },
            json=ticket,
            timeout=ITSM_TIMEOUT,
        )

    def create_ticket(self, ticket: dict, incident_id: str | None):
        if not self._token and not self._login():
            logger.warning(
                "Not logged in to ITSM, skipping ticket",
                extra={"incident_id": incident_id},
            )
            return

        response = self._post_ticket(ticket)
        # the token expired - login again and retry once
        if _is_unauthorized(response) and self._login():
            response = self._post_ticket(ticket)

        body = _json(response)
        if response.ok and body.get("status") is True:
            ticket_no = (body.get("responseObject") or {}).get("ticketNo")
            logger.info(
                f"Created ITSM ticket {ticket_no}",
                extra={"incident_id": incident_id, "ticket_no": ticket_no},
            )
        else:
            logger.error(
                "ITSM rejected the ticket",
                extra={
                    "incident_id": incident_id,
                    "status_code": response.status_code,
                    "response": response.text[:500],
                },
            )


_tickets_queue: queue.Queue | None = None
_tickets_queue_pid: int | None = None
_tickets_queue_lock = threading.Lock()


def _worker(tickets_queue: queue.Queue):
    client = _ItsmClient()
    while True:
        incident_id, ticket = tickets_queue.get()
        try:
            client.create_ticket(ticket, incident_id)
        except Exception:
            logger.exception(
                "Failed to create ITSM ticket", extra={"incident_id": incident_id}
            )


def _get_tickets_queue() -> queue.Queue:
    global _tickets_queue, _tickets_queue_pid
    # threads don't survive a fork, so every process starts its own worker
    if _tickets_queue_pid != os.getpid():
        with _tickets_queue_lock:
            if _tickets_queue_pid != os.getpid():
                _tickets_queue = queue.Queue(maxsize=QUEUE_SIZE)
                threading.Thread(
                    target=_worker,
                    args=(_tickets_queue,),
                    name="itsm-tickets",
                    daemon=True,
                ).start()
                _tickets_queue_pid = os.getpid()
    return _tickets_queue


def _build_ticket(incident: IncidentDto) -> dict:
    severity = str(getattr(incident.severity, "value", incident.severity) or "").lower()
    status = str(getattr(incident.status, "value", incident.status) or "").lower()
    name = incident.user_generated_name or incident.ai_generated_name or "Keep incident"
    description = str(incident.user_summary or incident.generated_summary or "")[
        :MAX_DESCRIPTION_LENGTH
    ]
    url = (
        f"{ITSM_KEEP_UI_URL.rstrip('/')}/incidents/{incident.id}"
        if ITSM_KEEP_UI_URL
        else None
    )
    details = {
        "Description": description,
        "Severity": severity,
        "Status": status,
        "Alerts": incident.alerts_count,
        "Sources": ", ".join(incident.alert_sources or []),
        "Services": ", ".join(incident.services or []),
        "Correlation rule": incident.rule_name,
        "Started": incident.start_time,
        "Keep incident id": incident.id,
        "URL": url,
    }
    remarks = "".join(
        f"<p><b>{label}:</b> {html.escape(str(value))}</p>"
        for label, value in details.items()
        if value
    )
    return {
        "formId": ITSM_FORM_ID,
        "customFields": [],
        "orgId": None,
        "categoryId": ITSM_CATEGORY_ID,
        "subCategoryId": ITSM_SUB_CATEGORY_ID,
        "severityId": ITSM_SEVERITY_MAP.get(severity, ITSM_DEFAULT_SEVERITY_ID),
        "title": str(name)[:MAX_TITLE_LENGTH],
        "remarks": remarks,
        "attachments": None,
        # Keep's incident UUID
        "referenceId": str(incident.id),
        "ticketSource": TICKET_SOURCE,
    }


def create_itsm_ticket_for_incident(tenant_id: str, incident: IncidentDto) -> None:
    """
    Queue an ITSM ticket for an incident Keep just created.

    The ticket is created in the background and this function never raises.
    """
    if not ITSM_INTEGRATION_ENABLED or incident is None:
        return

    if not (ITSM_LOGIN_EMAIL and ITSM_LOGIN_PASSWORD):
        logger.debug("ITSM credentials are not set, skipping ITSM ticket")
        return

    try:
        # AI suggestions that nobody confirmed yet are not real incidents
        if incident.is_candidate or not incident.is_visible:
            return
        ticket = _build_ticket(incident)
        try:
            _get_tickets_queue().put_nowait((str(incident.id), ticket))
        except queue.Full:
            logger.warning(
                "ITSM ticket queue is full, dropping ticket",
                extra={"tenant_id": tenant_id, "incident_id": str(incident.id)},
            )
    except Exception:
        logger.exception(
            "Failed to queue ITSM ticket",
            extra={"tenant_id": tenant_id, "incident_id": str(incident.id)},
        )
