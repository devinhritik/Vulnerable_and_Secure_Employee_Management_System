from django.db import models
from django.contrib.auth.models import User


class Employee(models.Model):
    ROLE_CHOICES = [
        ('employee', 'Employee'),
        ('manager', 'Manager'),
        ('admin', 'Admin'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    department = models.CharField(max_length=100)
    salary = models.DecimalField(max_digits=10, decimal_places=2)
    # VULNERABILITY #4 — Bio is stored and rendered without sanitization (XSS)
    bio = models.TextField(blank=True)
    # VULNERABILITY #6 — Role can be set by user during registration (mass assignment)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    # VULNERABILITY #7 — SSN stored and returned in API
    ssn = models.CharField(max_length=20, blank=True, verbose_name="SSN")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class AuditLog(models.Model):
    """Stores admin action logs"""
    action = models.CharField(max_length=200)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True)

    def __str__(self):
        return f"{self.action} by {self.performed_by} at {self.timestamp}"