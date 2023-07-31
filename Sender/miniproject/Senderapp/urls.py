from django.urls import path, include
from . import views
urlpatterns = [
    path('', views.home),
    path('encrypted/', views.userinput),
    path('encrypted/inputed/', views.forenc),
]
