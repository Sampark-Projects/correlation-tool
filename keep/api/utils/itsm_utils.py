import html
import json
import logging
import os
import queue
import threading
import time

import requests

from keep.api.core.config import config
from keep.api.models.alert import AlertDto, AlertStatus

# Sampark ITSM integration - every new firing alert Keep saves is opened as an ITSM ticket.
# Tickets are sent from a background thread and every error is logged and swallowed,
# so alert processing works exactly the same when the ITSM is down or not configured.

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
# only alerts with these statuses open a ticket (not resolved, acknowledged, etc.)
ITSM_ALERT_STATUSES = {
    status.strip().lower()
    for status in str(
        config("ITSM_ALERT_STATUSES", default=AlertStatus.FIRING.value)
    ).split(",")
    if status.strip()
}
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

    def create_ticket(self, ticket: dict, fingerprint: str | None):
        if not self._token and not self._login():
            logger.warning(
                "Not logged in to ITSM, skipping ticket",
                extra={"fingerprint": fingerprint},
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
                extra={"fingerprint": fingerprint, "ticket_no": ticket_no},
            )
        else:
            logger.error(
                "ITSM rejected the ticket",
                extra={
                    "fingerprint": fingerprint,
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
        fingerprint, ticket = tickets_queue.get()
        try:
            client.create_ticket(ticket, fingerprint)
        except Exception:
            logger.exception(
                "Failed to create ITSM ticket", extra={"fingerprint": fingerprint}
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


def _build_ticket(alert: AlertDto) -> dict | None:
    status = str(getattr(alert.status, "value", alert.status) or "").lower()
    if status not in ITSM_ALERT_STATUSES:
        return None

    severity = str(getattr(alert.severity, "value", alert.severity) or "").lower()
    description = str(alert.description or alert.message or "")[
        :MAX_DESCRIPTION_LENGTH
    ]
    # same fallback Keep uses for an alert with no source
    source = ", ".join(str(item) for item in alert.source or []) or "keep"
    details = {
        "Description": description,
        "Severity": severity,
        "Status": status,
        "Source": source,
        "Service": alert.service,
        "Environment": alert.environment,
        "Last received": alert.lastReceived,
        "Fingerprint": alert.fingerprint,
        "Keep alert id": alert.event_id,
        "URL": alert.url,
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
        "title": str(alert.name or "Keep alert")[:MAX_TITLE_LENGTH],
        "remarks": remarks,
        "attachments": None,
        "referenceId": source,
        "ticketSource": TICKET_SOURCE,
    }


def create_itsm_tickets(tenant_id: str, alerts: list[AlertDto]) -> None:
    """
    Queue an ITSM ticket for every new alert Keep saved.

    The tickets are created in the background and this function never raises.
    """
    if not ITSM_INTEGRATION_ENABLED or not alerts:
        return

    if not (ITSM_LOGIN_EMAIL and ITSM_LOGIN_PASSWORD):
        logger.debug("ITSM credentials are not set, skipping ITSM tickets")
        return

    try:
        tickets_queue = _get_tickets_queue()
        for alert in alerts:
            ticket = _build_ticket(alert)
            if ticket is None:
                continue
            try:
                tickets_queue.put_nowait((alert.fingerprint, ticket))
            except queue.Full:
                logger.warning(
                    "ITSM ticket queue is full, dropping ticket",
                    extra={"tenant_id": tenant_id, "fingerprint": alert.fingerprint},
                )
    except Exception:
        logger.exception("Failed to queue ITSM tickets", extra={"tenant_id": tenant_id})
