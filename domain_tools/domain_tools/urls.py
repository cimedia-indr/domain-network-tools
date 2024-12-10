"""
URL configuration for domain_tools project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path, include, URLResolver, URLPattern
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index),
    path('ping_test/', views.ping_test,name='ping_test'),
    path('dns_lookup/', views.dns_lookup,name='dns_lookup'),
    path('mx_check_view/', views.mx_check_view,name='mx_check_view'),
    path('reverse_ip_lookup/', views.reverse_ip_lookup,name='reverse_ip_lookup'),
    path('spf_check/', views.spf_check,name='spf_check'),
    path('dkim_check/',views.dkim_check,name='dkim_check'),
    
    
]
