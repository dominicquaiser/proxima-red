"""
WebSocket consumer for the live-note sync hot path (/ws/live/<uuid>/).

The socket replaces the HTTP poll loop, nothing else: updates are persisted
through the exact same service (same lock, same caps) and then broadcast to
the note's channel group, so WebSocket and polling clients interoperate on
one cursor space. Awareness frames (encrypted presence: cursor + selection +
name/color) are relayed to the group and never persisted; they are ephemeral
by design.

Access model: the scope twin of the views' ``_live_access_or_error``. A
link-mode note is anonymous (holding the link is the capability, exactly like
the HTTP endpoints); a restricted note (M4) additionally requires an
authenticated session (close WS_CLOSE_AUTH_REQUIRED) and a collaborator row
(close WS_CLOSE_FORBIDDEN). The session comes from SessionMiddlewareStack in
config/asgi.py and is read directly, because django.contrib.auth is not
installed (see ``_restricted_gate``).

Ordering contract: appends run under the service's row lock and every push
carries ``(prev_seq, seq)`` computed under that lock, so the client can
detect a missed frame (``prev_seq`` ahead of its cursor) and gap-heal with
one HTTP ``?since=`` fetch. Persist-then-broadcast: a row id is only ever
announced after its transaction committed.

Frames (JSON text):
- client -> server: {"type": "update", "txn": n, "payload": b64, "iv": b64,
                     "key_epoch": n} (key_epoch optional, absent reads as 0)
                    {"type": "awareness", "payload": b64, "iv": b64}
- server -> sender: {"type": "ack", "txn": n, "seq": id, "prev_seq": id,
                     "pending": n}
- server -> group:  {"type": "update", "seq": id, "prev_seq": id,
                     "payload": b64, "iv": b64} (sender excluded)
                    {"type": "awareness", "payload": b64, "iv": b64}
- server -> client: {"type": "error", "code": WS_ERROR_*}
                    {"type": "expired"} followed by close WS_CLOSE_NOT_FOUND

Close codes are terminal, error frames are recoverable (the socket stays
open): WS_CLOSE_NOT_FOUND (unknown or expired), WS_CLOSE_AUTH_REQUIRED /
WS_CLOSE_FORBIDDEN (restricted documents), WS_CLOSE_ABUSE (do not reconnect).

Abuse controls mirror the HTTP endpoints' posture (fail open on cache
trouble, per-IP buckets on the shared default cache): a per-IP connect
limit, a per-note concurrent-socket cap, per-frame size caps, and a
per-connection token bucket.
"""

import json
import logging
import time
import uuid

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from apps.auth.constants import SESSION_KEY_AUTHENTICATED, SESSION_KEY_USER_ID

from . import services
from .constants import (
    MAX_LIVE_AWARENESS_LENGTH,
    MAX_LIVE_UPDATE_LENGTH,
    MAX_LIVE_WS_PER_NOTE,
    RATE_LIMIT_LIVE_WS_CONNECT,
    WS_ABUSE_STREAK,
    WS_CLOSE_ABUSE,
    WS_CLOSE_AUTH_REQUIRED,
    WS_CLOSE_FORBIDDEN,
    WS_CLOSE_NOT_FOUND,
    WS_ERROR_AWARENESS_TOO_LARGE,
    WS_ERROR_INVALID_FRAME,
    WS_ERROR_RATE_LIMITED,
    WS_ERROR_SERVER,
    WS_ERROR_STALE_EPOCH,
    WS_ERROR_TAIL_FULL,
    WS_ERROR_UPDATE_TOO_LARGE,
    WS_MSG_BURST,
    WS_MSG_RATE,
    LOG_LIVE_WS_APPEND_FAILED,
)
from .models import LiveNote

logger = logging.getLogger(__name__)

# Cache-key prefixes for the consumer-side limits (default cache = the same
# Redis django-ratelimit uses in production, so the counters are consistent
# across workers).
CONNECT_BUCKET_PREFIX = "note:live:ws:connect:"
NOTE_SOCKETS_PREFIX = "note:live:ws:sockets:"
CONNECT_BUCKET_TTL = 60  # seconds; also the limit window
# Leak guard on the per-note socket counter: refreshed by every connect, so
# it only expires (and self-heals to zero) once a note has been idle.
NOTE_SOCKETS_TTL = 6 * 60 * 60


def scope_client_ip(scope) -> str:
    """Resolve the real client IP from an ASGI scope.

    The scope twin of ``apps.core.http.get_client_ip`` (same trusted-proxy
    semantics, same fail-open to the transport address): with
    ``RATELIMIT_TRUSTED_PROXY_COUNT`` trusted proxies, the client is the
    N-th-from-the-right ``X-Forwarded-For`` entry.

    Args:
        scope (dict): The ASGI connection scope.

    Returns:
        str: The resolved client IP (may be empty if unavailable).
    """
    from django.conf import settings

    trusted = getattr(settings, "RATELIMIT_TRUSTED_PROXY_COUNT", 0)
    if trusted > 0:
        forwarded = b""
        for name, value in scope.get("headers") or []:
            if name == b"x-forwarded-for":
                forwarded = value
                break
        parts = [
            part.strip()
            for part in forwarded.decode("latin1").split(",")
            if part.strip()
        ]
        if len(parts) >= trusted:
            return parts[-trusted]
    client = scope.get("client")
    return client[0] if client else ""


def _frame_payload_iv(content) -> tuple[str, str] | tuple[None, None]:
    """Extract a non-empty ``payload``/``iv`` string pair from a frame.

    Both the update and awareness handlers require the same two non-empty
    Base64 string fields; this is their shared shape check.

    Args:
        content (dict): The parsed inbound frame.

    Returns:
        tuple[str, str] | tuple[None, None]: The ``(payload, iv)`` pair, or
        ``(None, None)`` when either field is missing, non-string, or empty.
    """
    payload = content.get("payload")
    iv = content.get("iv")
    if isinstance(payload, str) and isinstance(iv, str) and payload and iv:
        return payload, iv
    return None, None


class TokenBucket:
    """Per-connection inbound-frame budget: ``burst`` tokens, ``rate``/s refill.

    Pure and clock-injected so the Python tests can drive it deterministically.
    """

    def __init__(self, burst: int, rate: float, now=time.monotonic):
        """Start the bucket full, so a client may burst immediately.

        Args:
            burst (int): Maximum tokens held at once, i.e. the largest burst
                allowed after an idle period.
            rate (float): Tokens refilled per second.
            now (callable): Zero-argument monotonic clock returning seconds.
                Injected by the tests; do not use a wall clock, which can jump.
        """
        self._burst = float(burst)
        self._rate = rate
        self._now = now
        self._allowance = float(burst)
        self._last = now()

    def allow(self) -> bool:
        """Consume one token if available.

        Returns:
            bool: True when the frame is within budget.
        """
        current = self._now()
        self._allowance = min(
            self._burst, self._allowance + (current - self._last) * self._rate
        )
        self._last = current
        if self._allowance < 1.0:
            return False
        self._allowance -= 1.0
        return True


def _cache_incr(key: str, ttl: int) -> int | None:
    """Increment a counter with a TTL set on first use; fail open.

    Args:
        key (str): Cache key.
        ttl (int): Expiry for a freshly created counter, in seconds.

    Returns:
        int | None: The counter value after incrementing, or ``None`` when
        the cache is unavailable (callers treat that as "allow").
    """
    try:
        if cache.add(key, 1, ttl):
            return 1
        return cache.incr(key)
    except Exception:
        return None


def _cache_decr(key: str) -> None:
    """Best-effort decrement for the per-note socket counter."""
    try:
        if cache.get(key, 0) > 0:
            cache.decr(key)
    except Exception:
        pass


class LiveNoteConsumer(AsyncJsonWebsocketConsumer):
    """One live-note editing session over WebSocket.

    One instance serves one connected editor; instances sharing a document
    find each other through the ``live.<uuid>`` channel-layer group.

    Attributes:
        note_id (uuid.UUID): The live note this session edits.
        group_name (str): Channel-layer group broadcasting this document.
        sockets_key (str): Cache key of the per-note concurrent-socket counter.
        expires_at (datetime.datetime): The note's expiry, read once at
            connect and re-checked per frame, so a session cannot outlive it.
    """

    # ── Connection lifecycle ─────────────────────────────────────────────

    async def connect(self):
        """Accept, run the gate checks, and join the note's group.

        Accept-then-close (rather than rejecting the handshake) so the
        browser client sees the application close code instead of a bare
        handshake failure it cannot distinguish from a network error.
        """
        self._joined_group = False
        self._counted_socket = False
        self._bucket = TokenBucket(WS_MSG_BURST, WS_MSG_RATE)
        self._over_budget_streak = 0

        pk = self.scope["url_route"]["kwargs"]["pk"]
        self.note_id: uuid.UUID = pk
        self.group_name = f"live.{pk}"
        self.sockets_key = NOTE_SOCKETS_PREFIX + str(pk)

        await self.accept()

        ip = scope_client_ip(self.scope)
        connects = _cache_incr(CONNECT_BUCKET_PREFIX + ip, CONNECT_BUCKET_TTL)
        if connects is not None and connects > RATE_LIMIT_LIVE_WS_CONNECT:
            await self.close(code=WS_CLOSE_ABUSE)
            return

        note_state = await self._load_active_note(pk)
        if note_state is None:
            await self.close(code=WS_CLOSE_NOT_FOUND)
            return
        self.expires_at = note_state["expires_at"]

        # Restricted-access gate (M4): link mode stays anonymous; a restricted
        # doc needs a session (close 4401) and a collaborator row (close 4403,
        # indistinguishable from 4404 by a non-collaborator who can't tell
        # restricted from missing). The gate runs in a DB thread because
        # reading the (lazy, DB-backed) scope session and the collaborator row
        # are both synchronous ORM operations.
        if note_state["access_mode"] == LiveNote.ACCESS_RESTRICTED:
            gate = await self._restricted_gate(pk)
            if gate == "no_session":
                await self.close(code=WS_CLOSE_AUTH_REQUIRED)
                return
            if gate == "forbidden":
                await self.close(code=WS_CLOSE_FORBIDDEN)
                return

        sockets = _cache_incr(self.sockets_key, NOTE_SOCKETS_TTL)
        self._counted_socket = sockets is not None
        if sockets is not None and sockets > MAX_LIVE_WS_PER_NOTE:
            await self.close(code=WS_CLOSE_ABUSE)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        self._joined_group = True

    async def disconnect(self, code):
        """Leave the group and release the per-note socket slot."""
        if self._joined_group:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        if self._counted_socket:
            self._counted_socket = False
            _cache_decr(self.sockets_key)

    # ── Inbound frames ───────────────────────────────────────────────────

    async def receive(self, text_data=None, bytes_data=None, **kwargs):
        """Parse one inbound frame defensively.

        Overrides the base class, which raises on malformed JSON and drops the
        socket. Here malformed input costs an error frame, not the connection.

        Args:
            text_data (str | None): The raw text frame, if the client sent one.
            bytes_data (bytes | None): Unused; binary frames are not part of
                the protocol and fall through to an ``invalid_frame`` error.
        """
        if text_data is None:
            await self._send_error(WS_ERROR_INVALID_FRAME)
            return
        try:
            content = json.loads(text_data)
        except ValueError:
            await self._send_error(WS_ERROR_INVALID_FRAME)
            return
        if not isinstance(content, dict):
            await self._send_error(WS_ERROR_INVALID_FRAME)
            return
        await self.receive_json(content)

    async def receive_json(self, content, **kwargs):
        """Dispatch one inbound frame through the expiry and budget gates."""
        if timezone.now() >= self.expires_at:
            # The doc expired mid-session. The cron sweep will delete the row;
            # this session is over either way.
            await self.send_json({"type": "expired"})
            await self.close(code=WS_CLOSE_NOT_FOUND)
            return

        frame_type = content.get("type")

        if not self._bucket.allow():
            self._over_budget_streak += 1
            if self._over_budget_streak >= WS_ABUSE_STREAK:
                await self.close(code=WS_CLOSE_ABUSE)
                return
            # Over-budget awareness is dropped silently (the next one
            # supersedes it anyway); updates get a parseable error frame.
            if frame_type == "update":
                await self._send_error(WS_ERROR_RATE_LIMITED)
            return
        self._over_budget_streak = 0

        if frame_type == "update":
            await self._handle_update(content)
        elif frame_type == "awareness":
            await self._handle_awareness(content)
        else:
            await self._send_error(WS_ERROR_INVALID_FRAME)

    async def _handle_update(self, content):
        """Persist one client-merged encrypted update, ack it, broadcast it."""
        payload, iv = _frame_payload_iv(content)
        if payload is None:
            await self._send_error(WS_ERROR_INVALID_FRAME)
            return
        if len(payload) > MAX_LIVE_UPDATE_LENGTH:
            await self._send_error(WS_ERROR_UPDATE_TOO_LARGE)
            return
        # Absent/invalid key_epoch reads as 0 (link-mode and pre-M4 clients);
        # a genuine mismatch surfaces as stale_epoch from the service.
        raw_epoch = content.get("key_epoch", 0)
        key_epoch = raw_epoch if isinstance(raw_epoch, int) and raw_epoch >= 0 else 0

        try:
            seq, pending, prev_seq = await self._append_update(payload, iv, key_epoch)
        except LiveNote.DoesNotExist:
            # Deleted by the expiry sweep between our connect and this frame.
            await self.send_json({"type": "expired"})
            await self.close(code=WS_CLOSE_NOT_FOUND)
            return
        except ValidationError as e:
            if e.code == "pending_tail_full":
                code = WS_ERROR_TAIL_FULL
            elif e.code == "stale_epoch":
                code = WS_ERROR_STALE_EPOCH
            else:
                code = WS_ERROR_INVALID_FRAME
            await self._send_error(code)
            return
        except Exception as e:
            logger.error(LOG_LIVE_WS_APPEND_FAILED, e.__class__.__name__)
            await self._send_error(WS_ERROR_SERVER)
            return

        # Persist-then-broadcast: the row committed above, so announcing its
        # id can never poison a cursor.
        await self.send_json(
            {
                "type": "ack",
                "txn": content.get("txn"),
                "seq": seq,
                "prev_seq": prev_seq,
                "pending": pending,
            }
        )
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "live.update",
                "seq": seq,
                "prev_seq": prev_seq,
                "payload": payload,
                "iv": iv,
                "sender": self.channel_name,
            },
        )

    async def _handle_awareness(self, content):
        """Relay one encrypted awareness update to the group; never persist."""
        payload, iv = _frame_payload_iv(content)
        if payload is None:
            await self._send_error(WS_ERROR_INVALID_FRAME)
            return
        if len(payload) > MAX_LIVE_AWARENESS_LENGTH:
            await self._send_error(WS_ERROR_AWARENESS_TOO_LARGE)
            return

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "live.awareness",
                "payload": payload,
                "iv": iv,
                "sender": self.channel_name,
            },
        )

    # ── Group events (channel layer -> this socket) ──────────────────────

    async def live_update(self, event):
        """Forward another client's committed update.

        The sender's own echo is skipped: it already advanced its cursor from
        the ack.
        """
        if event.get("sender") == self.channel_name:
            return
        await self.send_json(
            {
                "type": "update",
                "seq": event["seq"],
                "prev_seq": event["prev_seq"],
                "payload": event["payload"],
                "iv": event["iv"],
            }
        )

    async def live_awareness(self, event):
        """Forward another client's presence ciphertext."""
        if event.get("sender") == self.channel_name:
            return
        await self.send_json(
            {"type": "awareness", "payload": event["payload"], "iv": event["iv"]}
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _send_error(self, code: str):
        """Send a recoverable error frame, leaving the socket open.

        Args:
            code (str): One of the ``WS_ERROR_*`` constants.
        """
        await self.send_json({"type": "error", "code": code})

    @database_sync_to_async
    def _load_active_note(self, pk):
        """Fetch the note's expiry + access mode, deleting it if expired.

        Shares the expire-on-read gate (``services.get_active_live_note``)
        with the views' ``_live_note_or_404_json``, so unknown and expired are
        indistinguishable across both transports (both end in
        WS_CLOSE_NOT_FOUND here). Only the two fields needed to run the connect
        gate are returned, rather than the note itself, so nothing is held
        across the async boundary.

        Returns:
            dict | None: ``expires_at`` and ``access_mode``, or ``None`` when
            the note is gone.
        """
        note = services.get_active_live_note(pk)
        if note is None:
            return None
        return {"expires_at": note.expires_at, "access_mode": note.access_mode}

    @database_sync_to_async
    def _restricted_gate(self, pk) -> str:
        """Evaluate the restricted-access gate in a DB thread.

        Reads the custom session keys from the (lazy, DB-backed) scope
        session and checks for a collaborator row. django.contrib.auth is not
        installed, so the session is read directly (mirrors
        ``require_session_auth_api``).

        Returns:
            str: ``"ok"``, ``"no_session"`` (no authenticated session), or
            ``"forbidden"`` (authenticated but not a collaborator).
        """
        session = self.scope.get("session")
        user_id = (
            session.get(SESSION_KEY_USER_ID)
            if session and session.get(SESSION_KEY_AUTHENTICATED)
            else None
        )
        if not user_id:
            return "no_session"
        is_collaborator = LiveNote.objects.filter(
            pk=pk, collaborators__user__user_id=user_id
        ).exists()
        return "ok" if is_collaborator else "forbidden"

    @database_sync_to_async
    def _append_update(
        self, payload: str, iv: str, key_epoch: int
    ) -> tuple[int, int, int]:
        """Append one update in a DB thread, through the HTTP write path.

        Deliberately the same ``services.append_live_update`` the polling
        endpoint calls, so both transports share one lock, one set of caps,
        and one cursor space.

        Args:
            payload (str): Base64 ciphertext of one merged Yjs update.
            iv (str): Base64-encoded initialization vector.
            key_epoch (int): Document-key generation the client encrypted under.

        Returns:
            tuple[int, int, int]: The new row's id (the client's cursor), the
            pending tail size including it, and ``prev_seq``.

        Raises:
            LiveNote.DoesNotExist: If the note was deleted by the expiry sweep.
            ValidationError: Codes ``stale_epoch`` or ``pending_tail_full``.
        """
        row, pending, prev_seq = services.append_live_update(
            self.note_id, payload=payload, iv=iv, key_epoch=key_epoch
        )
        return row.pk, pending, prev_seq
