import re
import subprocess
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponseForbidden, JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Employee, AuditLog
from .serializers import EmployeeSerializer, UserSerializer


# ─────────────────────────────────────────────
# HELPER: Admin-only decorator
# ✅ FIX #5 — Reusable decorator enforces admin role on any view
# ─────────────────────────────────────────────

def admin_required(view_func):
    """Decorator: user must be logged in AND have role='admin'."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('/login/')
        try:
            if request.user.employee.role != 'admin':
                return HttpResponseForbidden("Access denied: Admins only.")
        except Employee.DoesNotExist:
            return HttpResponseForbidden("Access denied.")
        return view_func(request, *args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────
# AUTHENTICATION VIEWS
# ─────────────────────────────────────────────

# ✅ FIX #8 — @csrf_exempt REMOVED. CSRF token required for all POST forms.
def login_view(request):
    """
    ✅ FIX #1 — SQL Injection patched.
    authenticate() uses Django's ORM internally — parameterized queries only.
    The raw SQL string with f-string interpolation is completely gone.
    """
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        # ✅ FIX #1 — Django's authenticate() uses safe ORM lookups, never raw SQL
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('/dashboard/')
        else:
            error = "Invalid credentials"

    return render(request, 'login.html', {'error': error})


# ✅ FIX #8 — @csrf_exempt REMOVED
def register_view(request):
    """
    ✅ FIX #6 — Mass Assignment patched.
    The 'role' field from POST data is completely ignored.
    All new users are always created as 'employee'.
    """
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        email = request.POST.get('email', '').strip()
        bio = request.POST.get('bio', '')

        # ✅ FIX #6 — 'role' is NOT read from request.POST at all
        # role = request.POST.get('role')  ← this line is deleted

        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username taken'})

        user = User.objects.create_user(username=username, password=password, email=email)
        Employee.objects.create(
            user=user,
            name=username,
            email=email,
            department='General',
            salary=30000,
            role='employee',   # ✅ FIX #6 — Always 'employee', never from user input
            bio=bio,           # ✅ Bio stored as plain text; templates escape on output
        )
        return redirect('/login/')

    return render(request, 'register.html')


def logout_view(request):
    logout(request)
    return redirect('/login/')


# ─────────────────────────────────────────────
# MAIN PAGES
# ─────────────────────────────────────────────

@login_required(login_url='/login/')
def dashboard_view(request):
    employees = Employee.objects.all()
    return render(request, 'dashboard.html', {'employees': employees, 'user': request.user})


@login_required(login_url='/login/')
def profile_view(request, user_id):
    """
    ✅ FIX #3 — IDOR patched.
    Users can only view their OWN profile. Admins and managers may view all.

    ✅ FIX #4 — Stored XSS patched.
    mark_safe() is completely removed. Django templates auto-escape {{ bio }}
    so any HTML/JS in bio is rendered as harmless text, not executed code.
    """
    # ✅ FIX #3 — Ownership check: regular employees can only see themselves
    try:
        employee = Employee.objects.get(user_id=user_id)
    except Employee.DoesNotExist:
        return render(request, 'profile.html', {'error': 'Employee not found'})

    requesting_employee = getattr(request.user, 'employee', None)
    is_privileged = requesting_employee and requesting_employee.role in ('admin', 'manager')

    if not is_privileged and request.user.id != user_id:
        return HttpResponseForbidden("You can only view your own profile.")

    # ✅ FIX #4 — bio passed as plain string; template uses {{ bio }} NOT {{ safe_bio }}
    # Django's template engine escapes < > " ' & automatically
    return render(request, 'profile.html', {'employee': employee})


# ✅ FIX #8 — @csrf_exempt REMOVED
@login_required(login_url='/login/')
def edit_profile_view(request):
    """Bio is stored as-is but rendered safely by Django's auto-escaping."""
    try:
        employee = Employee.objects.get(user=request.user)
    except Employee.DoesNotExist:
        return redirect('/dashboard/')

    if request.method == 'POST':
        employee.bio = request.POST.get('bio', '')
        employee.phone = request.POST.get('phone', '')
        employee.address = request.POST.get('address', '')
        employee.save()
        return redirect(f'/profile/{request.user.id}/')

    return render(request, 'edit_profile.html', {'employee': employee})


@login_required(login_url='/login/')
def search_view(request):
    """
    ✅ FIX #1 — SQL Injection in search patched.
    Django ORM with __icontains performs parameterized queries automatically.
    The raw SQL f-string is completely removed.
    """
    results = []
    query_str = request.GET.get('q', '')

    if query_str:
        # ✅ FIX #1 — ORM query: Django builds a safe parameterized SQL statement
        results = Employee.objects.filter(
            name__icontains=query_str
        ) | Employee.objects.filter(
            department__icontains=query_str
        )

    return render(request, 'search.html', {'results': results, 'query': query_str})


# ─────────────────────────────────────────────
# ADMIN VIEWS
# ✅ FIX #5 — @admin_required enforces role check on every admin view
# ─────────────────────────────────────────────

@admin_required   # ✅ FIX #5 — Only admins can reach this page
def admin_panel_view(request):
    employees = Employee.objects.all()
    logs = AuditLog.objects.all().order_by('-timestamp')[:20]
    return render(request, 'admin_panel.html', {'employees': employees, 'logs': logs})


# ✅ FIX #8 — @csrf_exempt REMOVED
@admin_required   # ✅ FIX #5 — Admin only
def ping_view(request):
    """
    ✅ FIX #10 — Command Injection patched.
    Two layers of defense:
      1. Strict allowlist regex — only valid IP addresses or simple hostnames accepted.
      2. subprocess with a list argument (shell=False) — shell metacharacters are inert.
    os.popen() with shell=True is completely removed.
    """
    output = ''
    if request.method == 'POST':
        host = request.POST.get('host', '').strip()

        # ✅ FIX #10 — Layer 1: validate host is a safe IP or hostname
        # Blocks: 127.0.0.1 && whoami, 127.0.0.1; ls, 127.0.0.1 | id, etc.
        if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
            output = "Error: Invalid host. Only IP addresses and hostnames are allowed."
        else:
            # ✅ FIX #10 — Layer 2: subprocess list form — shell=False (default)
            # The OS treats each list item as a literal argument, never a shell command.
            try:
                result = subprocess.run(
                    ['ping', '-c', '2', host],  # ✅ No shell interpolation possible
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = result.stdout or result.stderr
            except subprocess.TimeoutExpired:
                output = "Error: Ping timed out."
            except Exception as e:
                output = f"Error: {e}"

    return render(request, 'ping.html', {'output': output})


# ─────────────────────────────────────────────
# API VIEWS
# ─────────────────────────────────────────────

# ✅ FIX #8 — @csrf_exempt REMOVED from all API views
# DRF uses token/JWT auth for APIs so CSRF is handled correctly by the framework

@api_view(['POST'])
@permission_classes([AllowAny])   # Login endpoint must be public
def api_login(request):
    """
    ✅ FIX #2 — JWT now uses strong key + short expiry (set in settings.py)
    ✅ FIX #7 — Response no longer includes password hash, SSN, or full employee data
    """
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)

    if user:
        refresh = RefreshToken.for_user(user)
        # ✅ FIX #7 — Return ONLY what the client genuinely needs
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user_id': user.id,
            'username': user.username,
            # ✅ password_hash REMOVED
            # ✅ employee data (including SSN) REMOVED
        })

    return Response({'error': 'Invalid credentials'}, status=401)


@api_view(['POST'])
@permission_classes([AllowAny])   # Registration must be public
def api_register(request):
    """
    ✅ FIX #6 — Mass Assignment patched via serializer.
    UserSerializer no longer has a 'role' field, so even if a user sends
    {"role": "admin"} it is silently ignored and 'employee' is used.
    """
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'Registered', 'user_id': user.id}, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_user_detail(request, user_id):
    """
    ✅ FIX #3 — IDOR patched.
    Users can only retrieve their own record. Admins may retrieve any.

    ✅ FIX #7 — Response no longer includes password hash or SSN.
    """
    # ✅ FIX #3 — Ownership check
    requesting_emp = getattr(request.user, 'employee', None)
    is_admin = requesting_emp and requesting_emp.role == 'admin'

    if not is_admin and request.user.id != user_id:
        return Response({'error': 'Forbidden'}, status=403)

    try:
        user = User.objects.get(id=user_id)
        employee = Employee.objects.get(user=user)
    except (User.DoesNotExist, Employee.DoesNotExist):
        return Response({'error': 'Not found'}, status=404)

    # ✅ FIX #7 — EmployeeSerializer only exposes safe fields (no SSN, no salary by default)
    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        # ✅ password_hash REMOVED
        'employee': EmployeeSerializer(employee).data,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_employees(request):
    """
    ✅ FIX — Authentication now required (was AllowAny).
    EmployeeSerializer exposes only safe fields.
    """
    employees = Employee.objects.all()
    return Response(EmployeeSerializer(employees, many=True).data)


# ✅ FIX #9 — /api/debug/ endpoint COMPLETELY REMOVED.
# It exposed SECRET_KEY, DB credentials, all user password hashes, and env vars.
# There is no legitimate reason for this endpoint to exist in any environment.