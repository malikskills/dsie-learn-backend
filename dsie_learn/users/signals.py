from django.db.models.signals import post_save
from django.dispatch import receiver

from dsie_learn.users.models import User
from dsie_learn.users.models import UserProfile


@receiver(post_save, sender=User)
def create_user_profile(*, instance: User, created: bool, **kwargs) -> None:
    """Create the one-to-one profile as soon as a user is created."""
    if created:
        UserProfile.objects.get_or_create(user=instance)
