"""
Tests for the note vault views: the vault page shell and the JSON APIs for
the encrypted index, the note rows, deletion, and the password-change
migration batch endpoint.

Follows the passwd vault test patterns: sessions are faked directly on the
test client, rate-limit buckets are cleared per test, and JSON endpoints are
exercised with the AJAX header.
"""

import json
import uuid

from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.auth.models import UserKeyPair
from apps.auth.tests.factories import (
    VALID_PUBLIC_KEY_B64,
    create_user_with_password,
    make_keypair,
)
from apps.note.constants import (
    MAX_VAULT_INDEX_LENGTH,
    MAX_VAULT_NOTE_CONTENT_LENGTH,
    MAX_VAULT_NOTES_PER_USER,
    VAULT_TRASH_RETENTION_DAYS,
)
from apps.note.models import VaultIndex, VaultNote

from .factories import (
    VALID_CONTENT_B64,
    VALID_IV_B64,
    make_vault_index,
    make_vault_note,
)

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}

# Strict Base64 the length validators can be pushed over with.
OVERSIZE_B64 = "AAAA" * (MAX_VAULT_NOTE_CONTENT_LENGTH // 4 + 1)
OVERSIZE_INDEX_B64 = "AAAA" * (MAX_VAULT_INDEX_LENGTH // 4 + 1)


class VaultTestCase(TestCase):
    """Shared setup: a user, a fresh client, cleared rate-limit buckets."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = create_user_with_password("correct horse battery staple")

    def _authenticate(self, user=None):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = (user or self.user).user_id
        session.save()

    def _post_json(self, url, payload):
        return self.client.post(
            url, json.dumps(payload), content_type="application/json", **AJAX
        )


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    NOTE_SITE_URL="https://note.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "note.proxima.red", "testserver"],
)
class NoteVaultViewTests(VaultTestCase):
    """The vault page: auth gate and the no-ciphertext-in-HTML guarantee.

    ``/vault/`` is host-dispatched by core (the note vault only answers on
    the note host), so these tests request it with an explicit host.
    """

    NOTE_HOST = {"HTTP_HOST": "note.proxima.red"}

    def test_unauthenticated_redirects_to_signin(self):
        response = self.client.get(reverse("note:vault"), **self.NOTE_HOST)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_authenticated_renders_vault(self):
        self._authenticate()
        response = self.client.get(reverse("note:vault"), **self.NOTE_HOST)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/vault.html")
        self.assertContains(response, self.user.user_id)

    def test_vault_page_hands_the_client_its_trash_settings(self):
        """The Trash endpoint and retention window reach the page.

        Both are read straight off ``dataset``, so a renamed attribute would
        silently give the client an ``undefined`` URL and a wrong-looking
        tooltip rather than fail loudly.
        """
        self._authenticate()
        response = self.client.get(reverse("note:vault"), **self.NOTE_HOST)
        self.assertContains(
            response, f'data-note-trash-url="{reverse("note:vault_note_trash")}"'
        )
        self.assertContains(
            response, f'data-trash-retention-days="{VAULT_TRASH_RETENTION_DAYS}"'
        )

    def test_vault_page_does_not_embed_ciphertext(self):
        """The shell never contains vault ciphertext; the browser fetches it
        only after the vault key is established."""
        make_vault_index(self.user, encrypted_data="aW5kZXhjaXBoZXJ0ZXh0")
        make_vault_note(self.user, content="bm90ZWNpcGhlcnRleHQ=")
        self._authenticate()
        response = self.client.get(reverse("note:vault"), **self.NOTE_HOST)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "aW5kZXhjaXBoZXJ0ZXh0")
        self.assertNotContains(response, "bm90ZWNpcGhlcnRleHQ=")


class VaultIndexViewTests(VaultTestCase):
    """GET/POST /vault/index/ - the encrypted index blob."""

    def test_get_requires_auth(self):
        response = self.client.get(reverse("note:vault_index"), **AJAX)
        self.assertEqual(response.status_code, 401)

    def test_post_requires_auth(self):
        response = self._post_json(
            reverse("note:vault_index"),
            {"encrypted_data": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 401)

    def test_get_without_index_returns_empty_success(self):
        self._authenticate()
        response = self.client.get(reverse("note:vault_index"), **AJAX)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"success": True})

    def test_round_trip(self):
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_index"),
            {"encrypted_data": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

        response = self.client.get(reverse("note:vault_index"), **AJAX)
        body = response.json()
        self.assertEqual(body["encrypted_data"], VALID_CONTENT_B64)
        self.assertEqual(body["iv"], VALID_IV_B64)

    def test_post_replaces_existing_index(self):
        make_vault_index(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_index"),
            {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(VaultIndex.objects.count(), 1)
        self.assertEqual(
            VaultIndex.objects.get(user=self.user).encrypted_data, "bmV3aW5kZXg="
        )

    def test_missing_fields_rejected(self):
        self._authenticate()
        for payload in (
            {},
            {"encrypted_data": VALID_CONTENT_B64},
            {"iv": VALID_IV_B64},
        ):
            response = self._post_json(reverse("note:vault_index"), payload)
            self.assertEqual(response.status_code, 400)

    def test_non_string_fields_rejected(self):
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_index"), {"encrypted_data": 42, "iv": VALID_IV_B64}
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_json_body_rejected(self):
        self._authenticate()
        response = self.client.post(
            reverse("note:vault_index"),
            "not json",
            content_type="application/json",
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)

    def test_oversized_blob_rejected(self):
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_index"),
            {"encrypted_data": OVERSIZE_INDEX_B64, "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(VaultIndex.objects.exists())

    def test_invalid_iv_rejected(self):
        self._authenticate()
        for bad_iv in ("no base64!!", "AAAA"):  # malformed / wrong byte length
            response = self._post_json(
                reverse("note:vault_index"),
                {"encrypted_data": VALID_CONTENT_B64, "iv": bad_iv},
            )
            self.assertEqual(response.status_code, 400)

    def test_session_for_deleted_user_returns_404(self):
        self._authenticate()
        self.user.delete()
        response = self.client.get(reverse("note:vault_index"), **AJAX)
        self.assertEqual(response.status_code, 404)


class VaultNoteCollectionViewTests(VaultTestCase):
    """GET/POST /vault/notes/ - listing and creating note rows."""

    def test_requires_auth(self):
        self.assertEqual(
            self.client.get(reverse("note:vault_notes"), **AJAX).status_code, 401
        )
        self.assertEqual(
            self._post_json(
                reverse("note:vault_notes"),
                {"content": VALID_CONTENT_B64, "iv": VALID_IV_B64},
            ).status_code,
            401,
        )

    def test_create_persists_owned_row(self):
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_notes"),
            {"content": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        note = VaultNote.objects.get(pk=body["note_id"])
        self.assertEqual(note.user, self.user)
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_create_validates_payload(self):
        self._authenticate()
        bad_payloads = [
            {"content": "not base64!!", "iv": VALID_IV_B64},
            {"content": OVERSIZE_B64, "iv": VALID_IV_B64},
            {"content": VALID_CONTENT_B64, "iv": "AAAA"},
            {"content": "", "iv": VALID_IV_B64},
        ]
        for payload in bad_payloads:
            response = self._post_json(reverse("note:vault_notes"), payload)
            self.assertEqual(response.status_code, 400, payload)
        self.assertFalse(VaultNote.objects.exists())

    def test_create_enforces_quota(self):
        self._authenticate()
        for _ in range(MAX_VAULT_NOTES_PER_USER):
            make_vault_note(self.user)
        response = self._post_json(
            reverse("note:vault_notes"),
            {"content": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(VaultNote.objects.count(), MAX_VAULT_NOTES_PER_USER)

    def test_list_returns_metadata_only(self):
        note = make_vault_note(self.user)
        self._authenticate()
        response = self.client.get(reverse("note:vault_notes"), **AJAX)
        body = response.json()
        self.assertEqual(len(body["notes"]), 1)
        entry = body["notes"][0]
        self.assertEqual(entry["id"], str(note.id))
        self.assertEqual(entry["size"], len(note.content))
        self.assertNotIn("content", entry)
        self.assertNotIn("iv", entry)

    def test_list_with_content_includes_ciphertext(self):
        note = make_vault_note(self.user)
        self._authenticate()
        response = self.client.get(
            reverse("note:vault_notes"), {"content": "1"}, **AJAX
        )
        entry = response.json()["notes"][0]
        self.assertEqual(entry["content"], note.content)
        self.assertEqual(entry["iv"], note.iv)

    def test_list_never_returns_foreign_rows(self):
        other = create_user_with_password("other user password")
        make_vault_note(other)
        self._authenticate()
        response = self.client.get(reverse("note:vault_notes"), **AJAX)
        self.assertEqual(response.json()["notes"], [])


class VaultNoteDetailViewTests(VaultTestCase):
    """GET/POST /vault/notes/<uuid>/ - reading and overwriting one row."""

    def test_requires_auth(self):
        note = make_vault_note(self.user)
        url = reverse("note:vault_note", args=[note.id])
        self.assertEqual(self.client.get(url, **AJAX).status_code, 401)

    def test_get_own_note(self):
        note = make_vault_note(self.user)
        self._authenticate()
        response = self.client.get(reverse("note:vault_note", args=[note.id]), **AJAX)
        body = response.json()
        self.assertEqual(body["id"], str(note.id))
        self.assertEqual(body["content"], note.content)
        self.assertEqual(body["iv"], note.iv)

    def test_foreign_note_is_404(self):
        other = create_user_with_password("other user password")
        note = make_vault_note(other)
        self._authenticate()
        response = self.client.get(reverse("note:vault_note", args=[note.id]), **AJAX)
        self.assertEqual(response.status_code, 404)

    def test_unknown_note_is_404(self):
        self._authenticate()
        response = self.client.get(
            reverse("note:vault_note", args=[uuid.uuid4()]), **AJAX
        )
        self.assertEqual(response.status_code, 404)

    def test_update_persists_and_bumps_updated_at(self):
        note = make_vault_note(self.user)
        original_updated_at = note.updated_at
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note", args=[note.id]),
            {"content": "bmV3Y29udGVudA==", "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 200)
        note.refresh_from_db()
        self.assertEqual(note.content, "bmV3Y29udGVudA==")
        self.assertGreater(note.updated_at, original_updated_at)

    def test_update_foreign_note_is_404(self):
        other = create_user_with_password("other user password")
        note = make_vault_note(other)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note", args=[note.id]),
            {"content": "bmV3Y29udGVudA==", "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 404)
        note.refresh_from_db()
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_update_validates_payload(self):
        note = make_vault_note(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note", args=[note.id]),
            {"content": "not base64!!", "iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 400)


class VaultNoteDeleteViewTests(VaultTestCase):
    """POST /vault/notes/<uuid>/delete/ - idempotent, owner-scoped delete."""

    def test_requires_auth(self):
        note = make_vault_note(self.user)
        url = reverse("note:vault_note_delete", args=[note.id])
        self.assertEqual(self._post_json(url, {}).status_code, 401)

    def test_deletes_owned_note(self):
        note = make_vault_note(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note_delete", args=[note.id]), {}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(VaultNote.objects.filter(pk=note.id).exists())

    def test_foreign_note_reports_success_without_deleting(self):
        other = create_user_with_password("other user password")
        note = make_vault_note(other)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note_delete", args=[note.id]), {}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(VaultNote.objects.filter(pk=note.id).exists())

    def test_unknown_note_reports_success(self):
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_note_delete", args=[uuid.uuid4()]), {}
        )
        self.assertEqual(response.status_code, 200)


class VaultNoteTrashViewTests(VaultTestCase):
    """POST /vault/notes/trash/ - the bulk, owner-scoped Trash flag."""

    def setUp(self):
        super().setUp()
        self.url = reverse("note:vault_note_trash")

    def test_requires_auth(self):
        note = make_vault_note(self.user)
        response = self._post_json(self.url, {"ids": [str(note.id)], "trashed": True})
        self.assertEqual(response.status_code, 401)

    def test_trashes_and_restores_in_bulk(self):
        first = make_vault_note(self.user)
        second = make_vault_note(self.user)
        self._authenticate()

        response = self._post_json(
            self.url, {"ids": [str(first.id), str(second.id)], "trashed": True}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated"], 2)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNotNone(first.trashed_at)
        self.assertIsNotNone(second.trashed_at)

        self._post_json(self.url, {"ids": [str(first.id)], "trashed": False})
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNone(first.trashed_at)
        self.assertIsNotNone(second.trashed_at)

    def test_is_owner_scoped(self):
        other = create_user_with_password("other user password")
        note = make_vault_note(other)
        self._authenticate()

        response = self._post_json(self.url, {"ids": [str(note.id)], "trashed": True})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated"], 0)
        note.refresh_from_db()
        self.assertIsNone(note.trashed_at)

    def test_repeating_the_call_is_harmless(self):
        note = make_vault_note(self.user)
        self._authenticate()

        self._post_json(self.url, {"ids": [str(note.id)], "trashed": True})
        note.refresh_from_db()
        first_stamp = note.trashed_at

        response = self._post_json(self.url, {"ids": [str(note.id)], "trashed": True})

        self.assertEqual(response.status_code, 200)
        note.refresh_from_db()
        self.assertGreaterEqual(note.trashed_at, first_stamp)

    def test_empty_id_list_is_accepted(self):
        self._authenticate()
        response = self._post_json(self.url, {"ids": [], "trashed": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated"], 0)

    def test_rejects_malformed_payloads(self):
        self._authenticate()
        note_id = str(make_vault_note(self.user).id)
        payloads = [
            {"trashed": True},  # no ids
            {"ids": note_id, "trashed": True},  # not a list
            {"ids": [1, 2], "trashed": True},  # not strings
            {"ids": [note_id]},  # no flag
            {"ids": [note_id], "trashed": "yes"},  # not a bool
            {"ids": [note_id] * (MAX_VAULT_NOTES_PER_USER + 1), "trashed": True},
        ]
        for payload in payloads:
            with self.subTest(payload=list(payload)):
                response = self._post_json(self.url, payload)
                self.assertEqual(response.status_code, 400)

        self.assertIsNone(VaultNote.objects.get(pk=note_id).trashed_at)

    def test_list_endpoint_reports_trash_state(self):
        note = make_vault_note(self.user)
        self._authenticate()
        self._post_json(self.url, {"ids": [str(note.id)], "trashed": True})

        response = self.client.get(reverse("note:vault_notes"), **AJAX)

        self.assertIsNotNone(response.json()["notes"][0]["trashed_at"])


class VaultMigrateViewTests(VaultTestCase):
    """POST /vault/migrate/ - the transactional password-change batch."""

    def test_requires_auth(self):
        response = self._post_json(reverse("note:vault_migrate"), {"notes": []})
        self.assertEqual(response.status_code, 401)

    def test_migrates_notes_and_index(self):
        first = make_vault_note(self.user)
        second = make_vault_note(self.user)
        make_vault_index(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [
                    {
                        "id": str(first.id),
                        "content": "Zmlyc3RuZXc=",
                        "iv": VALID_IV_B64,
                    },
                    {
                        "id": str(second.id),
                        "content": "c2Vjb25kbmV3",
                        "iv": VALID_IV_B64,
                    },
                ],
                "index": {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["migrated"], 2)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.content, "Zmlyc3RuZXc=")
        self.assertEqual(second.content, "c2Vjb25kbmV3")
        self.assertEqual(
            VaultIndex.objects.get(user=self.user).encrypted_data, "bmV3aW5kZXg="
        )

    def test_foreign_id_rolls_back_whole_batch(self):
        """Atomicity: one bad id must leave every row (and the index) untouched."""
        own = make_vault_note(self.user)
        other = create_user_with_password("other user password")
        foreign = make_vault_note(other)
        make_vault_index(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [
                    {"id": str(own.id), "content": "bmV3b3du", "iv": VALID_IV_B64},
                    {"id": str(foreign.id), "content": "c3RvbGVu", "iv": VALID_IV_B64},
                ],
                "index": {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
            },
        )
        self.assertEqual(response.status_code, 400)
        own.refresh_from_db()
        foreign.refresh_from_db()
        self.assertEqual(own.content, VALID_CONTENT_B64)
        self.assertEqual(foreign.content, VALID_CONTENT_B64)
        self.assertEqual(
            VaultIndex.objects.get(user=self.user).encrypted_data, VALID_CONTENT_B64
        )

    def test_index_only_migration(self):
        make_vault_index(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [],
                "index": {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["migrated"], 0)
        self.assertEqual(
            VaultIndex.objects.get(user=self.user).encrypted_data, "bmV3aW5kZXg="
        )

    def test_malformed_payload_shapes_rejected(self):
        self._authenticate()
        bad_payloads = [
            {"notes": "not a list"},
            {"notes": ["not a dict"]},
            {"notes": [{"id": "x", "content": VALID_CONTENT_B64}]},  # missing iv
            {"notes": [], "index": "not a dict"},
            {"notes": [], "index": {"encrypted_data": VALID_CONTENT_B64}},
        ]
        for payload in bad_payloads:
            response = self._post_json(reverse("note:vault_migrate"), payload)
            self.assertEqual(response.status_code, 400, payload)

    def test_malformed_note_id_rolls_back(self):
        """A non-UUID id reads as unknown and rolls the batch back."""
        own = make_vault_note(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [
                    {"id": str(own.id), "content": "bmV3b3du", "iv": VALID_IV_B64},
                    {"id": "not-a-uuid", "content": "eA==", "iv": VALID_IV_B64},
                ]
            },
        )
        self.assertEqual(response.status_code, 400)
        own.refresh_from_db()
        self.assertEqual(own.content, VALID_CONTENT_B64)

    def test_migrates_keypair_blob_with_index(self):
        """The re-encrypted private-key blob rides the final batch atomically."""
        make_keypair(self.user)
        make_vault_index(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [],
                "index": {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
                "keypair": {
                    "encrypted_private_key": "cmVrZXlwZWQ=",
                    "iv": VALID_IV_B64,
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        keypair = UserKeyPair.objects.get(user=self.user)
        # Only the blob rotates; the public key is unchanged.
        self.assertEqual(keypair.encrypted_private_key, "cmVrZXlwZWQ=")
        self.assertEqual(keypair.public_key, VALID_PUBLIC_KEY_B64)

    def test_keypair_only_migration(self):
        make_keypair(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [],
                "keypair": {
                    "encrypted_private_key": "b25seWtleQ==",
                    "iv": VALID_IV_B64,
                },
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            UserKeyPair.objects.get(user=self.user).encrypted_private_key,
            "b25seWtleQ==",
        )

    def test_keypair_payload_without_a_keypair_rolls_back(self):
        """A keypair blob for an account that has none fails the whole batch."""
        note = make_vault_note(self.user)
        self._authenticate()
        response = self._post_json(
            reverse("note:vault_migrate"),
            {
                "notes": [
                    {"id": str(note.id), "content": "bmV3b3du", "iv": VALID_IV_B64}
                ],
                "keypair": {"encrypted_private_key": "b3JwaGFu", "iv": VALID_IV_B64},
            },
        )
        self.assertEqual(response.status_code, 400)
        note.refresh_from_db()
        self.assertEqual(note.content, VALID_CONTENT_B64)  # rolled back

    def test_malformed_keypair_payload_rejected(self):
        make_keypair(self.user)
        self._authenticate()
        for keypair_payload in (
            "not a dict",
            {"encrypted_private_key": "eA=="},
            {"iv": VALID_IV_B64},
        ):
            response = self._post_json(
                reverse("note:vault_migrate"),
                {"notes": [], "keypair": keypair_payload},
            )
            self.assertEqual(response.status_code, 400, keypair_payload)


class VaultLifecycleTests(VaultTestCase):
    """Cross-cutting guarantees: cascade on account deletion, expiry safety."""

    def test_user_delete_cascades_vault_rows(self):
        make_vault_note(self.user)
        make_vault_index(self.user)
        self.user.delete()
        self.assertFalse(VaultNote.objects.exists())
        self.assertFalse(VaultIndex.objects.exists())

    def test_expired_note_sweep_leaves_vault_rows_untouched(self):
        """Vault notes have no expiry and must be invisible to the shared-note
        cleanup (it queries SharedNote only)."""
        from apps.note import services

        make_vault_note(self.user)
        deleted = services.delete_expired_notes()
        self.assertEqual(deleted, 0)
        self.assertEqual(VaultNote.objects.count(), 1)
