from django.urls import path
from . import views

urlpatterns = [
    # Web pages
    path('', views.dashboard_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/<int:user_id>/', views.profile_view, name='profile'),  # IDOR
    path('edit-profile/', views.edit_profile_view, name='edit_profile'),
    path('search/', views.search_view, name='search'),                    # SQL Injection

    # Admin pages (Broken Access Control)
    path('admin-panel/', views.admin_panel_view, name='admin_panel'),
    path('admin/ping/', views.ping_view, name='ping'),                    # Command Injection

    # API endpoints
    path('api/login/', views.api_login, name='api_login'),
    path('api/register/', views.api_register, name='api_register'),
    path('api/user/<int:user_id>/', views.api_user_detail, name='api_user_detail'),  # IDOR
    path('api/employees/', views.api_employees, name='api_employees'),
    path('api/debug/', views.api_debug, name='api_debug'),                # Debug exposure
]