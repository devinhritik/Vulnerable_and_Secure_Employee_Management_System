from django.urls import path
from . import views

urlpatterns = [
    # Web pages
    path('', views.dashboard_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/<int:user_id>/', views.profile_view, name='profile'),
    path('edit-profile/', views.edit_profile_view, name='edit_profile'),
    path('search/', views.search_view, name='search'),

    # Admin pages — protected by @admin_required
    path('admin-panel/', views.admin_panel_view, name='admin_panel'),
    path('admin/ping/', views.ping_view, name='ping'),

    # API endpoints
    path('api/login/', views.api_login, name='api_login'),
    path('api/register/', views.api_register, name='api_register'),
    path('api/user/<int:user_id>/', views.api_user_detail, name='api_user_detail'),
    path('api/employees/', views.api_employees, name='api_employees'),
    # ✅ FIX #9 — /api/debug/ REMOVED entirely
]