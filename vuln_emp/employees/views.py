import os
import json
import subprocess
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db import connection
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Employee, AuditLog
from .serializers import EmployeeSerializer, UserSerializer


# ─────────────────────────────────────────────
# AUTHENTICATION VIEWS
# ─────────────────────────────────────────────

@csrf_exempt  # VULNERABILITY #8 — CSRF protection disabled
def login_view(request):
    """
    VULNERABILITY #1 — SQL Injection in login
    The username is inserted directly into a raw SQL query.
    Try: username = ' OR '1'='1
    """
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        # VULNERABLE raw SQL — never do this!
        query = f"SELECT * FROM auth_user WHERE username = '{username}'"
        with connection.cursor() as cursor:
            cursor.execute(query)  # SQL INJECTION HERE
            row = cursor.fetchone()

        # Still authenticate properly for session (but SQL ran above)
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('/dashboard/')
        else:
            error = "Invalid credentials"

    return render(request, 'login.html', {'error': error})


@csrf_exempt  # VULNERABILITY #8
def register_view(request):
    """
    VULNERABILITY #6 — Mass Assignment
    User can pass role=admin in the POST body to make themselves admin.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email', '')
        # VULNERABILITY #6 — role comes directly from user input
        role = request.POST.get('role', 'employee')
        bio = request.POST.get('bio', '')

        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username taken'})

        user = User.objects.create_user(username=username, password=password, email=email)
        Employee.objects.create(
            user=user,
            name=username,
            email=email,
            department='General',
            salary=30000,
            role=role,   # VULNERABILITY — attacker sets role=admin
            bio=bio,
        )
        return redirect('/login/')

    return render(request, 'register.html')


def logout_view(request):
    logout(request)
    return redirect('/login/')


# ─────────────────────────────────────────────
# MAIN PAGES
# ─────────────────────────────────────────────

def dashboard_view(request):
    if not request.user.is_authenticated:
        return redirect('/login/')

    employees = Employee.objects.all()
    return render(request, 'dashboard.html', {'employees': employees, 'user': request.user})


def profile_view(request, user_id):
    """
    VULNERABILITY #3 — IDOR (Insecure Direct Object Reference)
    Any logged-in user can view ANY employee profile by changing the ID in the URL.
    E.g., /profile/1/, /profile/2/, /profile/3/ — no ownership check.
    """
    if not request.user.is_authenticated:
        return redirect('/login/')

    # No check: is this the current user's profile?
    try:
        employee = Employee.objects.get(user_id=user_id)  # IDOR — no ownership check
    except Employee.DoesNotExist:
        return render(request, 'profile.html', {'error': 'Employee not found'})

    # VULNERABILITY #4 — mark_safe() renders bio HTML without escaping (Stored XSS)
    # If bio contains <script>alert(1)</script>, it runs in the browser
    safe_bio = mark_safe(employee.bio)

    return render(request, 'profile.html', {'employee': employee, 'safe_bio': safe_bio})


@csrf_exempt  # VULNERABILITY #8
def edit_profile_view(request):
    """User edits their own profile — bio is stored raw (no sanitization)."""
    if not request.user.is_authenticated:
        return redirect('/login/')

    try:
        employee = Employee.objects.get(user=request.user)
    except Employee.DoesNotExist:
        return redirect('/dashboard/')

    if request.method == 'POST':
        employee.bio = request.POST.get('bio', '')  # VULNERABILITY #4 — stored XSS
        employee.phone = request.POST.get('phone', '')
        employee.address = request.POST.get('address', '')
        employee.save()
        return redirect(f'/profile/{request.user.id}/')

    return render(request, 'edit_profile.html', {'employee': employee})


def search_view(request):
    """
    VULNERABILITY #1 — SQL Injection in search
    Try searching: ' OR '1'='1' --
    Or: '; DROP TABLE employees_employee; --
    """
    if not request.user.is_authenticated:
        return redirect('/login/')

    results = []
    query_str = request.GET.get('q', '')

    if query_str:
        # VULNERABLE — raw SQL with user input injected directly
        sql = f"SELECT * FROM employees_employee WHERE name LIKE '%{query_str}%' OR department LIKE '%{query_str}%'"
        with connection.cursor() as cursor:
            cursor.execute(sql)  # SQL INJECTION HERE
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

    return render(request, 'search.html', {'results': results, 'query': query_str})


# ─────────────────────────────────────────────
# ADMIN VIEWS — VULNERABILITY #5: Broken Access Control
# These views check for login but NOT for admin role.
# Any regular user can access /admin-panel/, /admin/ping/, etc.
# ─────────────────────────────────────────────

def admin_panel_view(request):
    """
    VULNERABILITY #5 — Broken Access Control
    Only checks if logged in, not if user is actually an admin.
    Any employee can visit /admin-panel/
    """
    if not request.user.is_authenticated:
        return redirect('/login/')

    # MISSING: if not request.user.employee.role == 'admin': return 403

    employees = Employee.objects.all()
    logs = AuditLog.objects.all().order_by('-timestamp')[:20]
    return render(request, 'admin_panel.html', {'employees': employees, 'logs': logs})


@csrf_exempt  # VULNERABILITY #8
def ping_view(request):
    """
    VULNERABILITY #10 — Command Injection
    The 'host' parameter is passed directly to os.system() / ping command.
    Try: host = 127.0.0.1 && whoami
    Or:  host = 127.0.0.1; cat /etc/passwd
    """
    if not request.user.is_authenticated:
        return redirect('/login/')

    output = ''
    if request.method == 'POST':
        host = request.POST.get('host', '')
        # VULNERABILITY — user input directly in shell command
        command = f"ping -n 2 {host}"
        output = os.popen(command).read()  # COMMAND INJECTION HERE

    return render(request, 'ping.html', {'output': output})


# ─────────────────────────────────────────────
# API VIEWS
# ─────────────────────────────────────────────

@csrf_exempt  # VULNERABILITY #8
@api_view(['POST'])
def api_login(request):
    """
    VULNERABILITY #2 — Broken Auth (JWT with no expiry)
    VULNERABILITY #7 — Returns token + user data including password hash
    """
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)

    if user:
        refresh = RefreshToken.for_user(user)
        try:
            employee = Employee.objects.get(user=user)
            emp_data = EmployeeSerializer(employee).data
        except Employee.DoesNotExist:
            emp_data = {}

        # VULNERABILITY #7 — Returns way too much info including password hash
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user_id': user.id,
            'username': user.username,
            'password_hash': user.password,  # NEVER DO THIS
            'is_staff': user.is_staff,
            'employee': emp_data,            # Includes SSN, salary, etc.
        })

    return Response({'error': 'Invalid credentials'}, status=401)


@csrf_exempt  # VULNERABILITY #8
@api_view(['POST'])
def api_register(request):
    """
    VULNERABILITY #6 — Mass Assignment via API
    Send: {"username": "hacker", "password": "pass", "role": "admin"}
    """
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'Registered', 'user_id': user.id})
    return Response(serializer.errors, status=400)


@csrf_exempt  # VULNERABILITY #8
@api_view(['GET'])
def api_user_detail(request, user_id):
    """
    VULNERABILITY #3 — IDOR via API
    Any user can GET /api/user/1/, /api/user/2/, etc.
    VULNERABILITY #7 — Returns password hash, SSN, salary
    """
    # No authentication or ownership check
    try:
        user = User.objects.get(id=user_id)
        employee = Employee.objects.get(user=user)
    except (User.DoesNotExist, Employee.DoesNotExist):
        return Response({'error': 'Not found'}, status=404)

    # VULNERABILITY #7 — Returns sensitive data
    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password_hash': user.password,   # NEVER DO THIS
        'last_login': user.last_login,
        'employee': EmployeeSerializer(employee).data,  # Includes SSN
    })


@csrf_exempt  # VULNERABILITY #8
@api_view(['GET'])
def api_employees(request):
    """Returns all employees — no auth required."""
    employees = Employee.objects.all()
    return Response(EmployeeSerializer(employees, many=True).data)


@api_view(['GET'])
def api_debug(request):
    """
    VULNERABILITY #9 — Debug endpoint exposes server internals
    Visit /api/debug/ to see environment variables, installed apps, DB settings
    """
    import django.conf
    settings = django.conf.settings

    return Response({
        'SECRET_KEY': settings.SECRET_KEY,
        'DATABASES': str(settings.DATABASES),
        'INSTALLED_APPS': list(settings.INSTALLED_APPS),
        'DEBUG': settings.DEBUG,
        'environment_variables': dict(os.environ),  # Full env dump
        'users': list(User.objects.values('id', 'username', 'password', 'email')),
    })