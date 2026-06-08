from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Employee


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        # VULNERABILITY #7 — SSN and other sensitive fields are included in API response
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    # VULNERABILITY #6 — role can be passed in by the user (mass assignment)
    role = serializers.CharField(write_only=False, required=False)

    class Meta:
        model = User
        # VULNERABILITY #7 — password hash is returned in the API response
        fields = ['id', 'username', 'email', 'password', 'date_joined', 'last_login']

    def create(self, validated_data):
        role = validated_data.pop('role', 'employee')
        user = User.objects.create_user(**validated_data)

        # VULNERABILITY #6 — user-supplied role is used directly
        Employee.objects.create(
            user=user,
            name=user.username,
            email=user.email or '',
            department='Unassigned',
            salary=0,
            role=role,  # User controls this!
        )
        return user