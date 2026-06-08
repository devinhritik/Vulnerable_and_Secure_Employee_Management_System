from django.contrib import admin
from .models import Employee, AuditLog

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'department', 'role', 'salary']
    search_fields = ['name', 'email', 'department']
    list_filter = ['role', 'department']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['action', 'performed_by', 'timestamp']
    readonly_fields = ['timestamp']