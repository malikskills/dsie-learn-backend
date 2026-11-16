from allauth.account.decorators import secure_admin_login
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.utils.translation import gettext_lazy as _

from .forms import UserAdminChangeForm
from .forms import UserAdminCreationForm
from .models import OTP
from .models import Permission
from .models import Role
from .models import User
from .models import UserProfile

if settings.DJANGO_ADMIN_FORCE_ALLAUTH:
    # Force the `admin` sign in process to go through the `django-allauth` workflow:
    # https://docs.allauth.org/en/latest/common/admin.html#admin
    admin.autodiscover()
    admin.site.login = secure_admin_login(admin.site.login)  # type: ignore[method-assign]


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "email", "password1", "password2"),
            },
        ),
    )
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("name", "email")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "roles",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    list_display = ["username", "email", "name", "is_superuser", "is_active"]
    list_filter = ["is_active", "is_staff", "is_superuser", "roles"]
    search_fields = ["username", "name", "email"]
    filter_horizontal = ["roles", "groups", "user_permissions"]


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ["user", "phone_number", "timezone", "language", "updated_at"]
    list_select_related = ["user"]
    search_fields = ["user__username", "user__email", "user__name", "phone_number"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "is_active", "updated_at"]
    list_filter = ["is_active"]
    search_fields = ["code", "name", "description"]
    readonly_fields = ["created_at", "updated_at"]
    filter_horizontal = ["permissions"]


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ["code", "name", "is_active", "updated_at"]
    list_filter = ["is_active"]
    search_fields = ["code", "name", "description"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "purpose",
        "created_at",
        "expires_at",
        "attempts",
        "used_at",
        "invalidated_at",
    ]
    list_filter = ["purpose"]
    list_select_related = ["user"]
    search_fields = ["user__username", "user__email"]
    readonly_fields = [
        "user",
        "purpose",
        "code_hash",
        "created_at",
        "expires_at",
        "attempts",
        "max_attempts",
        "used_at",
        "invalidated_at",
    ]

    def has_add_permission(self, request) -> bool:
        """OTPs must be issued through OTP.issue(), never manually in the admin."""
        return False
