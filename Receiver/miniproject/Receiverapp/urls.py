from django.urls import path, include
from . import views
urlpatterns = [
    path('', views.home), 
    path('fordecryption/', views.decrypt),
    path('fordecryption/analysis/', views.analysis),
    path('fordecryption/attack/', views.attackhome), 
    path('fordecryption/attack/dictionary/', views.uploaddictionary),
    path('fordecryption/attack/bitflip/', views.bitflipattack),
    path('fordecryption/attack/dictionary/startattack/', views.dictionaryattack),
]
