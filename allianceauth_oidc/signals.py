from oauth2_provider import signals


def check_access(sender, request, token, *args, **kwargs):
    # TODO Check for access here
    pass


signals.app_authorized.connect(check_access)
