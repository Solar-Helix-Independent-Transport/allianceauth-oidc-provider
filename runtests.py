#!/usr/bin/env python
import os
import sys
from contextlib import nullcontext

USE_FAKE_REDIS = os.getenv("AA_USE_FAKE_REDIS", "1") == "1"

cm = nullcontext()

if USE_FAKE_REDIS:
    from unittest.mock import patch

    import fakeredis

    _fake_server = fakeredis.FakeServer()

    class AACompatFakeRedis(fakeredis.FakeRedis):
        def info(self, *args, **kwargs):
            return {"redis_version": "7.4.0"}

    def _fake_get_redis_connection(
        alias="default", write=True, *args, **kwargs
    ):
        return AACompatFakeRedis(server=_fake_server)

    cm = patch(
        "django_redis.get_redis_connection", new=_fake_get_redis_connection
    )


if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    with cm:
        sys.argv.insert(1, "test")
        execute_from_command_line(sys.argv)
