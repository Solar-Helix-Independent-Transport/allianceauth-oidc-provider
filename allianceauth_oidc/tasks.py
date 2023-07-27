from celery import shared_task
from oauth2_provider.models import clear_expired


@shared_task
def clear_expired_tokens():
    clear_expired()
