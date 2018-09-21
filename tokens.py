"""django.contrib.auth.tokens, but without using last_login in hash"""
import datetime
from datetime import date
from django.conf import settings
from django.utils.http import int_to_base36, base36_to_int
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils import six
from datetime import datetime, timedelta

from sigapi.models import AuthUserToken


class TokenGenerator(object):
    """
    Strategy object used to generate and check tokens
    reset mechanism.
    """
    def make_token(self, user):
        """
        Returns a token that can be used once
        for the given user.
        """
        return self._make_token_with_timestamp(user, self._num_days(self._today()))

    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user.
        """
        # Parse the token
        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit
        if (self._num_days(self._today()) - ts) > getattr(settings, 'TOKEN_TIMEOUT_DAYS', 7):
            return False

        return True

    def _make_token_with_timestamp(self, user, timestamp):
        # timestamp is number of days since 2001-1-1.  Converted to
        # base 36, this gives us a 3 digit string until about 2121
        ts_b36 = int_to_base36(timestamp)

        key_salt = "tokenapi.tokens.PasswordResetTokenGenerator"

        value = (six.text_type(user.username) + six.text_type(timestamp))
        hash = salted_hmac(key_salt, value).hexdigest()[::2]
        token = "%s-%s" % (ts_b36, hash)
        self._save_token(user=user, token=token)
        return token

    def _num_days(self, dt):
        return (dt - date(2001, 1, 1)).days

    def _today(self):
        # Used for mocking in tests
        return date.today()

    def _save_token(self, user, token):
        exptime = datetime.now() + timedelta(days=getattr(settings, 'TOKEN_TIMEOUT_DAYS', 7))
        AuthUserToken.objects.update_or_create(username=user.username, defaults={
            'token': token,
            'expiretime': exptime
        })


token_generator = TokenGenerator()
