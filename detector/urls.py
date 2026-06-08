from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('history/', views.history, name='history'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('bulk-scan/', views.bulk_scan, name='bulk_scan'),
    path('email-scan/', views.email_scan, name='email_scan'),
    path('email-scan/callback/', views.email_scan_callback, name='email_scan_callback'),
]