"""
Tests for the live-note WebSocket consumer (apps/note/consumers.py).

Run against the real ASGI entrypoint (config.asgi.application) so the origin
validator and routing are exercised too. The channel layer is the in-memory
backend from the shared settings; Django TestCase's async support runs the
consumer's ORM calls (database_sync_to_async) on the test transaction.
"""

import json
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

# channels.testing's __init__ unconditionally imports its live-server test
# case, which needs daphne: deliberately not installed (uvicorn is the ASGI
# server here). Satisfy that one import with a stub; nothing in this suite
# touches ChannelsLiveServerTestCase.
import sys
import types

if "daphne" not in sys.modules:  # pragma: no branch
    _daphne = types.ModuleType("daphne")
    _daphne_testing = types.ModuleType("daphne.testing")
    _daphne_testing.DaphneProcess = object
    _daphne.testing = _daphne_testing
    sys.modules["daphne"] = _daphne
    sys.modules["daphne.testing"] = _daphne_testing

from channels.testing.websocket import WebsocketCommunicator  # noqa: E402

from apps.note.constants import (
    WS_CLOSE_ABUSE,
    WS_CLOSE_AUTH_REQUIRED,
    WS_CLOSE_FORBIDDEN,
    WS_CLOSE_NOT_FOUND,
    WS_ERROR_AWARENESS_TOO_LARGE,
    WS_ERROR_INVALID_FRAME,
    WS_ERROR_STALE_EPOCH,
    WS_ERROR_TAIL_FULL,
    WS_ERROR_UPDATE_TOO_LARGE,
)
from apps.note.consumers import TokenBucket, scope_client_ip
from apps.note.models import LiveNote, LiveNoteUpdate

from .factories import (
    VALID_CONTENT_B64,
    VALID_IV_B64,
    make_live_collaborator,
    make_live_note,
    make_live_update,
    make_restricted_live_note,
)

# Imported late so config.asgi initialises against the test settings.
from config.asgi import application  # noqa: E402

ORIGIN_HEADERS = [(b"origin", b"http://testserver"), (b"host", b"testserver")]


def ws_path(note_id) -> str:
    return f"/ws/live/{note_id}/"


class LiveConsumerTestCase(TestCase):
    """Shared plumbing: fresh cache buckets and communicator helpers."""

    def setUp(self):
        cache.clear()  # reset connect/socket counters between tests
        self._open = []

    async def asyncTearDown(self):  # pragma: no cover - safety net
        for communicator in self._open:
            await communicator.disconnect()

    async def _connect(self, note_id, expect_accept=True, session_user=None):
        headers = list(ORIGIN_HEADERS)
        if session_user is not None:
            cookie = await self._session_cookie(session_user)
            headers.append((b"cookie", cookie.encode("latin1")))
        communicator = WebsocketCommunicator(
            application, ws_path(note_id), headers=headers
        )
        self._open.append(communicator)
        connected, _subprotocol = await communicator.connect()
        if expect_accept:
            self.assertTrue(connected)
        return communicator

    @staticmethod
    async def _session_cookie(user) -> str:
        """Create an authenticated session and return its Cookie header value.

        The consumer reads the custom session keys through
        SessionMiddlewareStack, so a real signed session cookie is needed.
        """
        from channels.db import database_sync_to_async
        from django.conf import settings
        from importlib import import_module

        @database_sync_to_async
        def build():
            engine = import_module(settings.SESSION_ENGINE)
            store = engine.SessionStore()
            store["authenticated"] = True
            store["user_id"] = user.user_id
            store.create()
            return f"{settings.SESSION_COOKIE_NAME}={store.session_key}"

        return await build()

    async def _close_all(self):
        for communicator in self._open:
            await communicator.disconnect()
        self._open = []


class LiveConsumerConnectTests(LiveConsumerTestCase):
    """Connection gates: unknown/expired notes, connect limits, socket caps."""

    async def test_unknown_note_closes_4404(self):
        communicator = await self._connect("00000000-0000-0000-0000-000000000000")
        message = await communicator.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_NOT_FOUND)
        await self._close_all()

    async def test_expired_note_is_deleted_and_closes_4404(self):
        note = await self._make_note(expired=True)
        communicator = await self._connect(note.pk)
        message = await communicator.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_NOT_FOUND)
        exists = await self._note_exists(note.pk)
        self.assertFalse(exists)
        await self._close_all()

    async def test_connect_rate_limit_closes_4429(self):
        note = await self._make_note()
        with patch("apps.note.consumers.RATE_LIMIT_LIVE_WS_CONNECT", 2):
            await self._connect(note.pk)
            await self._connect(note.pk)
            third = await self._connect(note.pk)
            message = await third.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_ABUSE)
        await self._close_all()

    async def test_per_note_socket_cap_closes_4429(self):
        note = await self._make_note()
        with patch("apps.note.consumers.MAX_LIVE_WS_PER_NOTE", 1):
            await self._connect(note.pk)
            second = await self._connect(note.pk)
            message = await second.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_ABUSE)
        await self._close_all()

    async def test_disconnect_releases_the_socket_slot(self):
        note = await self._make_note()
        with patch("apps.note.consumers.MAX_LIVE_WS_PER_NOTE", 1):
            first = await self._connect(note.pk)
            await first.disconnect()
            second = await self._connect(note.pk)
            # A healthy connection has no pending output.
            self.assertTrue(await second.receive_nothing())
        await self._close_all()

    @staticmethod
    async def _make_note(expired=False):
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def build():
            note = make_live_note()
            if expired:
                note.expires_at = timezone.now() - timedelta(minutes=1)
                note.save(update_fields=["expires_at"])
            return note

        return await build()

    @staticmethod
    async def _note_exists(pk):
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def check():
            return LiveNote.objects.filter(pk=pk).exists()

        return await check()


class LiveConsumerUpdateTests(LiveConsumerTestCase):
    """Update frames: persist, ack, broadcast, and the error mapping."""

    async def test_update_persists_acks_and_broadcasts_excluding_sender(self):
        note = await LiveConsumerConnectTests._make_note()
        sender = await self._connect(note.pk)
        receiver = await self._connect(note.pk)

        await sender.send_json_to(
            {
                "type": "update",
                "txn": 7,
                "payload": VALID_CONTENT_B64,
                "iv": VALID_IV_B64,
            }
        )

        ack = await sender.receive_json_from()
        self.assertEqual(ack["type"], "ack")
        self.assertEqual(ack["txn"], 7)
        self.assertEqual(ack["pending"], 1)
        self.assertEqual(ack["prev_seq"], 0)  # fresh note: snapshot_seq

        broadcast = await receiver.receive_json_from()
        self.assertEqual(broadcast["type"], "update")
        self.assertEqual(broadcast["seq"], ack["seq"])
        self.assertEqual(broadcast["prev_seq"], ack["prev_seq"])
        self.assertEqual(broadcast["payload"], VALID_CONTENT_B64)
        self.assertEqual(broadcast["iv"], VALID_IV_B64)

        # The sender got the ack only, no own echo.
        self.assertTrue(await sender.receive_nothing())

        persisted = await self._row_count(note.pk)
        self.assertEqual(persisted, 1)
        await self._close_all()

    async def test_oversize_update_gets_error_frame_and_stays_connected(self):
        note = await LiveConsumerConnectTests._make_note()
        communicator = await self._connect(note.pk)

        with patch("apps.note.consumers.MAX_LIVE_UPDATE_LENGTH", 4):
            await communicator.send_json_to(
                {"type": "update", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
            )
            reply = await communicator.receive_json_from()

        self.assertEqual(reply, {"type": "error", "code": WS_ERROR_UPDATE_TOO_LARGE})
        persisted = await self._row_count(note.pk)
        self.assertEqual(persisted, 0)
        await self._close_all()

    async def test_full_tail_maps_to_pending_tail_full_error_frame(self):
        note = await LiveConsumerConnectTests._make_note()
        await self._seed_row(note)
        communicator = await self._connect(note.pk)

        with patch("apps.note.services.MAX_LIVE_PENDING_UPDATES", 1):
            await communicator.send_json_to(
                {"type": "update", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
            )
            reply = await communicator.receive_json_from()

        self.assertEqual(reply, {"type": "error", "code": WS_ERROR_TAIL_FULL})
        await self._close_all()

    async def test_malformed_frames_get_invalid_frame_not_a_dropped_socket(self):
        note = await LiveConsumerConnectTests._make_note()
        communicator = await self._connect(note.pk)

        await communicator.send_to(text_data="not json")
        reply = await communicator.receive_json_from()
        self.assertEqual(reply["code"], WS_ERROR_INVALID_FRAME)

        await communicator.send_to(text_data=json.dumps(["a", "list"]))
        reply = await communicator.receive_json_from()
        self.assertEqual(reply["code"], WS_ERROR_INVALID_FRAME)

        await communicator.send_json_to({"type": "unknown"})
        reply = await communicator.receive_json_from()
        self.assertEqual(reply["code"], WS_ERROR_INVALID_FRAME)

        # Still connected and functional after all three.
        await communicator.send_json_to(
            {"type": "update", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
        )
        ack = await communicator.receive_json_from()
        self.assertEqual(ack["type"], "ack")
        await self._close_all()

    async def test_expired_mid_session_sends_expired_then_4404(self):
        # The consumer checks the expiry it cached at connect (expires_at is
        # fixed at creation, so the cache is always accurate in production);
        # advance the consumer's clock past it.
        note = await LiveConsumerConnectTests._make_note()
        communicator = await self._connect(note.pk)

        future = timezone.now() + timedelta(days=365)
        with patch("apps.note.consumers.timezone") as frozen:
            frozen.now.return_value = future
            await communicator.send_json_to(
                {"type": "update", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
            )
            reply = await communicator.receive_json_from()
            self.assertEqual(reply, {"type": "expired"})
            message = await communicator.receive_output()

        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_NOT_FOUND)
        await self._close_all()

    async def test_note_deleted_by_sweep_mid_session_sends_expired_then_4404(self):
        note = await LiveConsumerConnectTests._make_note()
        communicator = await self._connect(note.pk)

        await self._delete_note(note.pk)
        await communicator.send_json_to(
            {"type": "update", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
        )

        reply = await communicator.receive_json_from()
        self.assertEqual(reply, {"type": "expired"})
        message = await communicator.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_NOT_FOUND)
        await self._close_all()

    @staticmethod
    async def _row_count(pk):
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def count():
            return LiveNoteUpdate.objects.filter(note_id=pk).count()

        return await count()

    @staticmethod
    async def _seed_row(note):
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def seed():
            make_live_update(note)

        await seed()

    @staticmethod
    async def _delete_note(pk):
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def remove():
            LiveNote.objects.filter(pk=pk).delete()

        await remove()


class LiveConsumerAwarenessTests(LiveConsumerTestCase):
    """Awareness frames: relayed to peers, never persisted, size-capped."""

    async def test_awareness_relays_to_peers_and_is_not_persisted(self):
        note = await LiveConsumerConnectTests._make_note()
        sender = await self._connect(note.pk)
        receiver = await self._connect(note.pk)

        await sender.send_json_to(
            {"type": "awareness", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
        )

        relayed = await receiver.receive_json_from()
        self.assertEqual(
            relayed,
            {"type": "awareness", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )
        # No ack, no own echo, and nothing hits the database.
        self.assertTrue(await sender.receive_nothing())
        persisted = await LiveConsumerUpdateTests._row_count(note.pk)
        self.assertEqual(persisted, 0)
        await self._close_all()

    async def test_oversize_awareness_gets_error_frame_and_is_not_relayed(self):
        note = await LiveConsumerConnectTests._make_note()
        sender = await self._connect(note.pk)
        receiver = await self._connect(note.pk)

        with patch("apps.note.consumers.MAX_LIVE_AWARENESS_LENGTH", 4):
            await sender.send_json_to(
                {"type": "awareness", "payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
            )
            reply = await sender.receive_json_from()

        self.assertEqual(reply, {"type": "error", "code": WS_ERROR_AWARENESS_TOO_LARGE})
        self.assertTrue(await receiver.receive_nothing())
        await self._close_all()


class LiveConsumerRestrictedTests(LiveConsumerTestCase):
    """The restricted-access connect gate (M4 named collaborators)."""

    async def test_link_note_stays_anonymous(self):
        note = await LiveConsumerConnectTests._make_note()
        communicator = await self._connect(note.pk)
        self.assertTrue(await communicator.receive_nothing())
        await self._close_all()

    async def test_restricted_note_without_session_closes_4401(self):
        note = await self._make_restricted()
        communicator = await self._connect(note.pk)
        message = await communicator.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_AUTH_REQUIRED)
        await self._close_all()

    async def test_restricted_note_non_collaborator_closes_4403(self):
        note, _owner = await self._make_restricted(return_owner=True)
        stranger = await self._make_user("stranger secret")
        communicator = await self._connect(note.pk, session_user=stranger)
        message = await communicator.receive_output()
        self.assertEqual(message["type"], "websocket.close")
        self.assertEqual(message["code"], WS_CLOSE_FORBIDDEN)
        await self._close_all()

    async def test_restricted_note_collaborator_connects(self):
        note, owner = await self._make_restricted(return_owner=True)
        communicator = await self._connect(note.pk, session_user=owner)
        self.assertTrue(await communicator.receive_nothing())
        await self._close_all()

    async def test_stale_epoch_update_gets_error_frame(self):
        note, owner = await self._make_restricted(return_owner=True, key_epoch=2)
        communicator = await self._connect(note.pk, session_user=owner)
        await communicator.send_json_to(
            {
                "type": "update",
                "payload": VALID_CONTENT_B64,
                "iv": VALID_IV_B64,
                "key_epoch": 1,
            }
        )
        reply = await communicator.receive_json_from()
        self.assertEqual(reply, {"type": "error", "code": WS_ERROR_STALE_EPOCH})
        await self._close_all()

    @staticmethod
    async def _make_user(secret):
        from channels.db import database_sync_to_async
        from apps.auth.tests.factories import create_user_with_password

        return await database_sync_to_async(create_user_with_password)(secret)

    @staticmethod
    async def _make_restricted(return_owner=False, key_epoch=0):
        from channels.db import database_sync_to_async
        from apps.auth.tests.factories import create_user_with_password

        @database_sync_to_async
        def build():
            owner = create_user_with_password("owner secret")
            note = make_restricted_live_note(owner)
            if key_epoch:
                note.key_epoch = key_epoch
                note.save(update_fields=["key_epoch"])
                # keep the owner grant at the note's epoch so they remain valid
                note.collaborators.update(key_epoch=key_epoch)
            return note, owner

        note, owner = await build()
        return (note, owner) if return_owner else note


class TokenBucketTests(TestCase):
    """The pure per-connection frame budget."""

    def test_burst_then_refill(self):
        clock = {"t": 0.0}
        bucket = TokenBucket(2, 1.0, now=lambda: clock["t"])

        self.assertTrue(bucket.allow())
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())  # burst exhausted

        clock["t"] = 1.0  # one second -> one token refilled
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())

    def test_refill_never_exceeds_burst(self):
        clock = {"t": 0.0}
        bucket = TokenBucket(3, 10.0, now=lambda: clock["t"])
        clock["t"] = 100.0  # long idle: allowance caps at burst
        self.assertTrue(bucket.allow())
        self.assertTrue(bucket.allow())
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())


class ScopeClientIpTests(TestCase):
    """The scope twin of apps.core.http.get_client_ip."""

    def test_uses_transport_address_without_trusted_proxies(self):
        scope = {"client": ("203.0.113.7", 4711), "headers": []}
        self.assertEqual(scope_client_ip(scope), "203.0.113.7")

    def test_reads_rightmost_trusted_forwarded_entry(self):
        scope = {
            "client": ("10.0.0.1", 4711),
            "headers": [(b"x-forwarded-for", b"1.2.3.4, 203.0.113.7")],
        }
        with self.settings(RATELIMIT_TRUSTED_PROXY_COUNT=1):
            self.assertEqual(scope_client_ip(scope), "203.0.113.7")
        with self.settings(RATELIMIT_TRUSTED_PROXY_COUNT=2):
            self.assertEqual(scope_client_ip(scope), "1.2.3.4")

    def test_falls_back_when_header_is_shorter_than_the_chain(self):
        scope = {
            "client": ("10.0.0.1", 4711),
            "headers": [(b"x-forwarded-for", b"203.0.113.7")],
        }
        with self.settings(RATELIMIT_TRUSTED_PROXY_COUNT=2):
            self.assertEqual(scope_client_ip(scope), "10.0.0.1")

    def test_empty_scope_yields_empty_string(self):
        self.assertEqual(scope_client_ip({"headers": []}), "")
