# coding=utf-8
from functools import wraps

from django.http import HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt

import time

from django.contrib.auth import get_user_model

from sigapi.models import AuthUserToken
from sigapi.tokens import token_generator
import hmac
import hashlib


def sign_required(view_func):
    """Decorator which ensures the user has provided a correct sign."""

    @csrf_exempt
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        username = None
        signature = None
        timestamp = None

        username = request.POST.get('username', request.GET.get('username'))
        signature = request.POST.get('signature', request.GET.get('signature'))
        timestamp = request.POST.get('timestamp', request.GET.get('timestamp'))

        if not (username and signature and timestamp):
            return HttpResponseForbidden("Must include 'username', 'signature' and 'timestamp' parameters with request.")

        user = authenticate(timestamp=timestamp, signature=signature, username=username)
        if user:
            request.user = user
            return view_func(request, *args, **kwargs)

        return HttpResponseForbidden()
    return _wrapped_view


def authenticate(timestamp=0, signature='', username=''):
    # 查看用户是否存在
    try:
        user = get_user_model().objects.get(username=username)
    except get_user_model().DoesNotExist:
        return None

    # Reject users with is_active=False. Custom user models that don't have
    # that attribute are allowed.
    is_active = getattr(user, 'is_active', None)
    if (is_active or is_active is None) and checkSignature(timestamp=timestamp, signature=signature, user=user):
        return user


def checkSignature(timestamp=0, signature='', user=None):
    """
    检查请求签名是否合法
    首先token没有过期
    而且签名符合
    :param timestamp:
    :param signature:
    :param username:
    :return: boolean
    """
    # 参数异常
    if timestamp == 0 and signature == '' and user is None:
        return False

    current_time = time.time()
    # 5分钟之前的请求，不予回应
    try:
        if current_time - float(timestamp) > 300.0:
            return False
    except Exception as e:
        return False

    access_name = user.username
    hash_string = "%s\n%s" % (timestamp, access_name)
    hash_string = hash_string.encode('ascii', 'ignore')
    access_token = AuthUserToken.objects.get(username=access_name).token
    access_token = access_token.encode('ascii', 'ignore')

    # 查看token是否正确
    is_token_valid = token_generator.check_token(user, access_token)
    if not is_token_valid:
        return False

    # 查看签名是否正确
    ssig = hmac.new(access_token, hash_string, hashlib.sha1).hexdigest()[10:15]
    if ssig == signature.encode('ascii', 'ignore'):
        return True
    else:
        return False
