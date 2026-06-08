from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Employee


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        # ✅ FIX #7 — Explicit field list. SSN and sensitive fields are NOT included.
        fields = ['id', 'name', 'email', 'department', 'role', 'phone', 'bio', 'created_at']
        # Note: salary is intentionally excluded from the public API too.


class UserSerializer(serializers.ModelSerializer):
    # ✅ FIX #6 — role field REMOVED. Users cannot set their own role via the API.

    class Meta:
        model = User
        # ✅ FIX #7 — password hash is NEVER returned. Only write_only for creation.
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},  # ✅ Password accepted for creation, never returned
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)

        # ✅ FIX #6 — Role is always hardcoded to 'employee' regardless of what user sent
        Employee.objects.create(
            user=user,
            name=user.username,
            email=user.email or '',
            department='Unassigned',
            salary=0,
            role='employee',   # ✅ Hardcoded — user has zero control over this
        )
        return user