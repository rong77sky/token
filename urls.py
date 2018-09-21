from django.conf.urls import url

from sigapi.views import token_new


urlpatterns = [
    url(r'^token/new.json$', token_new, name='api_token_new'),
]
