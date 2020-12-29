"""vanscan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.index),
    path('scan',views.Scan),
    path('whatweb',views.Whatweb.as_view()),
    path('awvs13', views.Awvs13.as_view()),
    path('api/awvs13/info', views.Awvs13.info),
    path('api/awvs13/moreadd', views.awvs13.moreadd),
    path('api/awvs13/getvulns', views.awvs13.get_vluns),
    path('api/awvs13/getvulinfo', views.awvs13.get_vulinfo),
    path('api/awvs13/delscan', views.awvs13.del_scan),
    path('api/awvs13/stopscan', views.awvs13.stop_scan),
    path('api/awvs13/Presentation', views.awvs13.Presentation),
    
    


]
