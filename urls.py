from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('encrypt', views.get_result, name='encrypt'),
    path('Shannon', views.theory1, name='theory1'),
    path('Aes', views.theory2, name='theory2'),
]
