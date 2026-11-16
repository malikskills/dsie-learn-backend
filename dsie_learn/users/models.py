from __future__ import annotations

import secrets
from datetime import datetime
from datetime import timedelta
from zoneinfo import ZoneInfo
from zoneinfo import ZoneInfoNotFoundError

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

IDENTIFIER_VALIDATOR = RegexValidator(
    regex=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$",
    message=_(
        "Use lowercase identifiers separated by dots (for example, 'courses.create').",
    ),
    code="invalid_identifier",
)

PHONE_NUMBER_VALIDATOR = RegexValidator(
    regex=r"^\+[1-9]\d{7,14}$",
    message=_("Enter a phone number in E.164 format (for example, +237690000000)."),
    code="invalid_phone_number",
)


def validate_timezone(value: str) -> None:
    """Require a valid IANA time-zone identifier."""
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as error:
        raise ValidationError(_("Enter a valid IANA time zone.")) from error


class Permission(models.Model):
    """A business permission that can be granted through a :class:`Role`."""

    code = models.CharField(
        _("code"),
        max_length=100,
        unique=True,
        validators=[IDENTIFIER_VALIDATOR],
        help_text=_("Stable machine-readable identifier, e.g. 'courses.publish'."),
    )
    name = models.CharField(_("name"), max_length=150)
    description = models.TextField(_("description"), blank=True)
    is_active = models.BooleanField(_("active"), default=True)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        ordering = ["code"]
        verbose_name = _("permission")
        verbose_name_plural = _("permissions")
        indexes = [models.Index(fields=["is_active", "code"])]

    def __str__(self) -> str:
        return self.code

    def save(self, *args, **kwargs) -> None:
        self.code = self.code.strip().lower()
        super().save(*args, **kwargs)


class Role(models.Model):
    """A named collection of business permissions for role-based access control."""

    code = models.CharField(
        _("code"),
        max_length=100,
        unique=True,
        validators=[IDENTIFIER_VALIDATOR],
        help_text=_("Stable machine-readable identifier, e.g. 'instructor'."),
    )
    name = models.CharField(_("name"), max_length=150)
    description = models.TextField(_("description"), blank=True)
    permissions = models.ManyToManyField(
        Permission,
        related_name="roles",
        blank=True,
        verbose_name=_("permissions"),
    )
    is_active = models.BooleanField(_("active"), default=True)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        ordering = ["code"]
        verbose_name = _("role")
        verbose_name_plural = _("roles")
        indexes = [models.Index(fields=["is_active", "code"])]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        self.code = self.code.strip().lower()
        super().save(*args, **kwargs)


class User(AbstractUser):
    """Application user with profile and role-based access assignments."""

    # First and last name do not cover name patterns around the globe.
    name = models.CharField(_("full name"), blank=True, max_length=255)
    first_name = None  # type: ignore[assignment]
    last_name = None  # type: ignore[assignment]
    email = models.EmailField(_("email address"), unique=True)
    roles = models.ManyToManyField(
        Role,
        related_name="users",
        blank=True,
        verbose_name=_("roles"),
    )

    REQUIRED_FIELDS = ["email"]

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")

    def __str__(self) -> str:
        return self.username

    def save(self, *args, **kwargs) -> None:
        self.name = self.name.strip()
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def get_full_name(self) -> str:
        """Return the user's display name, falling back to their username."""
        return self.name or self.username

    def get_short_name(self) -> str:
        """Return the short display name used by Django and django-allauth."""
        return self.get_full_name()

    def get_absolute_url(self) -> str:
        """Return the URL for this user's public detail view."""
        return reverse("users:detail", kwargs={"username": self.username})

    def has_role(self, role_code: str) -> bool:
        """Return whether this active user has an active role with ``role_code``."""
        if not self.pk or not self.is_active:
            return False
        return bool(self.roles.filter(is_active=True, code=role_code.lower()).exists())

    def get_role_permissions(self) -> models.QuerySet[Permission]:
        """Return the distinct active permissions inherited from active roles."""
        if not self.pk:
            return Permission.objects.none()

        return Permission.objects.filter(
            is_active=True,
            roles__is_active=True,
            roles__users=self,
        ).distinct()

    def has_role_permission(self, permission_code: str) -> bool:
        """Return whether an active user may perform a business action.

        This complements Django's ``has_perm`` instead of replacing it: built-in
        model permissions and application RBAC remain separate.
        """
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        return self.get_role_permissions().filter(code=permission_code.lower()).exists()


class UserProfile(models.Model):
    """Personal and presentation data kept separate from authentication data."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
        verbose_name=_("user"),
    )
    avatar = models.ImageField(_("avatar"), upload_to="avatars/%Y/%m/", blank=True)
    bio = models.TextField(_("biography"), blank=True, max_length=1_000)
    phone_number = models.CharField(
        _("phone number"),
        max_length=16,
        blank=True,
        validators=[PHONE_NUMBER_VALIDATOR],
        help_text=_("Stored in international E.164 format."),
    )
    timezone = models.CharField(
        _("time zone"),
        max_length=63,
        default=settings.TIME_ZONE,
        validators=[validate_timezone],
        help_text=_("IANA time zone, for example 'Africa/Douala'."),
    )
    language = models.CharField(
        _("preferred language"),
        max_length=10,
        default=settings.LANGUAGE_CODE,
    )
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        verbose_name = _("user profile")
        verbose_name_plural = _("user profiles")

    def __str__(self) -> str:
        return _("Profile for %(username)s") % {"username": self.user.username}


class OTP(models.Model):
    """A single-use, hashed OTP for a security-sensitive user action.

    Raw codes are generated by :meth:`issue` and returned once to the caller; they
    are never persisted. Consumers should deliver the returned code over their
    chosen trusted channel, then call :meth:`verify` to consume it.
    """

    class Purpose(models.TextChoices):
        LOGIN = "login", _("Login")
        EMAIL_VERIFICATION = "email_verification", _("Email verification")
        PASSWORD_RESET = "password_reset", _("Password reset")

    CODE_LENGTH = 6
    DEFAULT_TTL = timedelta(minutes=10)
    DEFAULT_MAX_ATTEMPTS = 5

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="otps",
        verbose_name=_("user"),
    )
    purpose = models.CharField(_("purpose"), max_length=32, choices=Purpose.choices)
    code_hash = models.CharField(_("code hash"), max_length=256, editable=False)
    expires_at = models.DateTimeField(_("expires at"))
    attempts = models.PositiveSmallIntegerField(
        _("attempts"),
        default=0,
        editable=False,
    )
    max_attempts = models.PositiveSmallIntegerField(
        _("maximum attempts"),
        default=DEFAULT_MAX_ATTEMPTS,
        editable=False,
    )
    used_at = models.DateTimeField(_("used at"), null=True, blank=True, editable=False)
    invalidated_at = models.DateTimeField(
        _("invalidated at"),
        null=True,
        blank=True,
        editable=False,
    )
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("one-time password")
        verbose_name_plural = _("one-time passwords")
        indexes = [
            models.Index(fields=["user", "purpose", "-created_at"]),
            models.Index(fields=["expires_at"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(max_attempts__gte=1),
                name="otp_max_attempts_at_least_one",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user} — {self.get_purpose_display()}"

    def clean(self) -> None:
        super().clean()
        if self.pk and self.expires_at <= self.created_at:
            raise ValidationError({"expires_at": _("Expiry must be after issuance.")})

    @classmethod
    def issue(
        cls,
        user: User,
        purpose: Purpose | str,
        *,
        ttl: timedelta = DEFAULT_TTL,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> tuple[OTP, str]:
        """Create an OTP and return ``(otp, raw_code)`` exactly once.

        Any still-active OTP for the same user and purpose is invalidated first.
        Row locking makes concurrent issuance requests deterministic.
        """
        if not user.pk:
            msg = "Saved user required."
            raise ValueError(msg)
        if ttl <= timedelta():
            msg = "Positive OTP TTL required."
            raise ValueError(msg)
        if max_attempts < 1:
            msg = "Positive maximum attempts required."
            raise ValueError(msg)

        purpose_value = cls.Purpose(purpose).value
        now = timezone.now()
        raw_code = f"{secrets.randbelow(10**cls.CODE_LENGTH):0{cls.CODE_LENGTH}d}"

        with transaction.atomic():
            cls.objects.select_for_update().filter(
                user=user,
                purpose=purpose_value,
                used_at__isnull=True,
                invalidated_at__isnull=True,
                expires_at__gt=now,
            ).update(invalidated_at=now)
            otp = cls.objects.create(
                user=user,
                purpose=purpose_value,
                code_hash=make_password(raw_code),
                expires_at=now + ttl,
                max_attempts=max_attempts,
            )

        return otp, raw_code

    def is_valid_at(self, moment: datetime) -> bool:
        """Return whether this OTP can be verified at ``moment``."""
        return bool(
            self.used_at is None
            and self.invalidated_at is None
            and self.expires_at > moment
            and self.attempts < self.max_attempts,
        )

    @property
    def is_valid(self) -> bool:
        """Return whether this OTP is currently usable."""
        return self.is_valid_at(timezone.now())

    def verify(self, raw_code: str) -> bool:
        """Verify and consume this OTP atomically.

        Failed active attempts are recorded. The OTP becomes invalid when its
        attempt limit is reached, and successful verification makes it single-use.
        """
        if not self.pk:
            msg = "Saved OTP required."
            raise ValueError(msg)

        with transaction.atomic():
            otp = type(self).objects.select_for_update().get(pk=self.pk)
            now = timezone.now()

            if not otp.is_valid_at(now):
                self.refresh_from_db()
                return False

            if check_password(raw_code, otp.code_hash):
                otp.used_at = now
                otp.save(update_fields=["used_at"])
                self.refresh_from_db()
                return True

            otp.attempts += 1
            update_fields = ["attempts"]
            if otp.attempts >= otp.max_attempts:
                otp.invalidated_at = now
                update_fields.append("invalidated_at")
            otp.save(update_fields=update_fields)
            self.refresh_from_db()
            return False
