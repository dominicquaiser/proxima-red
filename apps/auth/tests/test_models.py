"""Tests for the authentication models."""

from django.test import TestCase

from apps.auth.constants import USER_ID_LENGTH
from apps.auth.models import User, generate_user_id


class UserModelTests(TestCase):
    """Test cases for User model."""

    def test_generate_user_id(self):
        """Test user_id generation creates 8-digit numeric ID."""
        user_id = generate_user_id()
        self.assertEqual(len(user_id), USER_ID_LENGTH)
        self.assertTrue(user_id.isdigit())

    def test_user_creation(self):
        """Test creating a user with all required fields."""
        user = User.objects.create(password_hash="test_hash", vault_salt="test_salt")
        self.assertIsNotNone(user.user_id)
        self.assertEqual(len(user.user_id), USER_ID_LENGTH)
        self.assertTrue(user.user_id.isdigit())
        self.assertIsNotNone(user.created_at)
        self.assertIsNotNone(user.updated_at)

    def test_user_str_representation(self):
        """Test string representation of User model."""
        user = User.objects.create(password_hash="test_hash", vault_salt="test_salt")
        expected = f"User {user.user_id}"
        self.assertEqual(str(user), expected)

    def test_user_repr(self):
        """repr() includes the user_id and the creation timestamp."""
        user = User.objects.create(password_hash="test_hash", vault_salt="test_salt")
        expected = (
            f"<User user_id={user.user_id} created={user.created_at.isoformat()}>"
        )
        self.assertEqual(repr(user), expected)

    def test_unique_user_id(self):
        """Test that user_id is unique across users."""
        user1 = User.objects.create(password_hash="test_hash1", vault_salt="test_salt1")
        user2 = User.objects.create(password_hash="test_hash2", vault_salt="test_salt2")
        self.assertNotEqual(user1.user_id, user2.user_id)
