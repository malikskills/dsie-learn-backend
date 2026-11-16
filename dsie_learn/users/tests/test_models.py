from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from django.utils import timezone

from dsie_learn.users.models import OTP
from dsie_learn.users.models import Permission
from dsie_learn.users.models import Role
from dsie_learn.users.models import UserProfile

if TYPE_CHECKING:
    from dsie_learn.users.models import User


def test_user_get_absolute_url(user: User):
    assert user.get_absolute_url() == f"/users/{user.username}/"


@pytest.mark.django_db
def test_user_profile_is_created_with_user(user: User):
    profile = user.profile

    assert isinstance(profile, UserProfile)
    assert profile.user == user


@pytest.mark.django_db
def test_user_inherits_active_permissions_from_active_roles(user: User):
    permission = Permission.objects.create(
        code="courses.publish",
        name="Publish courses",
    )
    inactive_permission = Permission.objects.create(
        code="courses.archive",
        name="Archive courses",
        is_active=False,
    )
    role = Role.objects.create(code="instructor", name="Instructor")
    role.permissions.add(permission, inactive_permission)
    user.roles.add(role)

    assert user.has_role("INSTRUCTOR")
    assert user.has_role_permission("COURSES.PUBLISH")
    assert not user.has_role_permission("courses.archive")

    role.is_active = False
    role.save(update_fields=["is_active"])

    assert not user.has_role("instructor")
    assert not user.has_role_permission("courses.publish")


@pytest.mark.django_db
def test_otp_is_hashed_single_use_and_invalidates_previous_code(user: User):
    first_otp, first_code = OTP.issue(user, OTP.Purpose.LOGIN)
    second_otp, second_code = OTP.issue(user, OTP.Purpose.LOGIN)

    first_otp.refresh_from_db()
    assert first_otp.invalidated_at is not None
    assert first_code not in first_otp.code_hash
    assert second_code not in second_otp.code_hash
    assert not first_otp.verify(first_code)
    assert second_otp.verify(second_code)
    assert second_otp.used_at is not None
    assert not second_otp.verify(second_code)


@pytest.mark.django_db
def test_otp_expires_and_locks_after_its_maximum_attempts(user: User):
    expired_otp, expired_code = OTP.issue(
        user,
        OTP.Purpose.EMAIL_VERIFICATION,
        ttl=timedelta(microseconds=1),
    )
    assert expired_code
    expired_otp.expires_at = timezone.now() - timedelta(seconds=1)
    expired_otp.save(update_fields=["expires_at"])
    assert not expired_otp.verify(expired_code)

    max_attempts = 2
    otp, _ = OTP.issue(user, OTP.Purpose.PASSWORD_RESET, max_attempts=max_attempts)
    assert not otp.verify("000000")
    assert not otp.verify("000000")
    assert otp.attempts == max_attempts
    assert otp.invalidated_at is not None
