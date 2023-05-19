from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('classify/', views.classify_view, name='classify'),
    path('result/', views.result, name='result'),
    path('error/', views.error, name='error'),
]

