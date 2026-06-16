"""
Request handlers for the core app.

INTENTIONALLY-VULNERABLE TEST FIXTURE. Each endpoint below contains a
deliberately planted vulnerability for use by a defensive security scanner.
Do NOT deploy this code.
"""
import requests
import yaml
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from core.ingest import deserialize


@csrf_exempt
def config(request):
    """
    (A) SCA endpoint: POST /api/config

    Loads a YAML document supplied in the raw request body. PyYAML 5.1's
    default Loader for yaml.load() permits construction of arbitrary Python
    objects, so attacker-controlled YAML tags can execute arbitrary code.
    """
    if request.method != "POST":
        return HttpResponse(status=405)

    # SCA: PyYAML 5.1 CVE-2020-1747 - unsafe yaml.load on request body
    data = yaml.load(request.body)

    return JsonResponse({"loaded": str(data)})


@csrf_exempt
def proxy(request):
    """
    (B) CHAIN endpoint: GET /api/proxy?url=  (cross-file chain)

    Step 1 fetches an attacker-supplied URL (SSRF) here in core/views.py. The
    fetched response body then flows into core/ingest.deserialize() (step 2,
    pickle.loads) in a separate module, giving the attacker control over the
    deserialized bytes and hence remote code execution.
    """
    url = request.GET.get("url", "")

    # CHAIN step 1/2 (SSRF) — source in core/views.py
    r = requests.get(url)

    # The bytes fetched above flow into the deserialization sink in core/ingest.py.
    obj = deserialize(r.content)

    return JsonResponse({"deserialized": str(obj)})


def user(request):
    """
    (C) NORMAL endpoint: GET /api/user?name=

    Looks up a user by name using a SQL query built via string formatting of
    request input, allowing classic SQL injection.
    """
    name = request.GET.get("name", "")

    with connection.cursor() as cursor:
        # NORMAL: SQL injection
        cursor.execute(
            "SELECT id, username FROM auth_user WHERE username = '%s'" % name
        )
        rows = cursor.fetchall()

    return JsonResponse({"rows": rows})
