from django.conf import settings
from django.http.response import JsonResponse
import json

def did_document(request):
    with open(settings.DID_DOCUMENT_FILE) as f:
        data = json.load(f)
    return JsonResponse(data)
