from django.views.decorators.csrf import csrf_exempt

from pipeline.models import AuthUser
from sigapi.tokens import token_generator
from sigapi.http import JsonResponse, JsonResponseUnauthorized, JsonResponseForbidden, JsonResponseNotAllowed
from django.conf import settings


@csrf_exempt
def token_new(request):
    # if request.method == 'POST' and request.user.is_authenticated() and request.user.is_supeuser:
    if request.method == 'POST':
        username = request.POST.get('username')
        auth_key = request.POST.get('auth_key', 'wrong')

        if auth_key != getattr(settings, 'SECRET_KEY'):
            return JsonResponseForbidden("param auth_key incorrect")

        try:
            user = AuthUser.objects.get(username=username)
        except AuthUser.DoesNotExist:
            user = None

        if user:
            if not user.is_active:
                return JsonResponseForbidden("User account is disabled.")

            data = {
                'token': token_generator.make_token(user),
                'username': user.username,
            }
            return JsonResponse(data)
        else:
            return JsonResponseUnauthorized("Please login http://pipeline.corpautohome.com first.")
    else:
        return JsonResponseNotAllowed("Use POST request please")

