## Vulnerable_&_Secure_Employee_Management_System


# Security Lab

A hands-on learning project comparing a **vulnerable** Django app 
against its **fixed** secure version.

## Structure
- `vul_emp/` — Intentionally vulnerable Django app (10 vulnerabilities)
- `fixed_emp/` — Patched secure version with all fixes applied

## Vulnerabilities Covered
1. SQL Injection
2. Broken Authentication (Weak JWT)
3. IDOR (Insecure Direct Object Reference)
4. Stored XSS
5. Broken Access Control
6. Mass Assignment
7. Sensitive Data Exposure
8. CSRF Disabled
9. DEBUG=True / Hardcoded Secrets
10. Command Injection

## Setup — Vulnerable App
```bash
cd vul_emp
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## Setup — Fixed App
```bash
cd fixed_emp
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
# Create .env file with SECRET_KEY and JWT_SIGNING_KEY
python manage.py migrate
python manage.py runserver
```

## Warning
The vulnerable app is intentionally insecure.
**Never deploy it to a public server.**

