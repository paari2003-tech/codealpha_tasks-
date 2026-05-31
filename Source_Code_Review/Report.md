# Secure Code Review — Findings Report
## Internship Task 3 | CodeAlpha Cybersecurity Internship
### Reviewed by: Paari S
### Date: 31st May 2026
### Language: Python
### File Audited: vulnerable_Sample.py
### Tool Used: Bandit 1.9.4

## 1. Overview

This report documents the findings of a secure code review performed on a 
deliberately vulnerable Python application. The goal was to identify security 
vulnerabilities, demonstrate their real world impact, fix them using secure 
coding practices and verify the fixes using the Bandit static analyzer.


## 2. Vulnerabilities Found

### Vulnerability 1 — SQL Injection
- **Severity:** Medium
- **CWE:** CWE-89
- **Location:** Line 65 — vul_login() function
- **Bandit Rule:** B608 — hardcoded_sql_expressions

**Vulnerable Code:**
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

**What the attacker does:**
Types admin' -- as the username. The -- comments out the password check entirely.
The attacker logs in without knowing the password.

**Real World Impact:**
- Login bypass without credentials
- Full database access
- Data theft or deletion

**Fix Applied:**
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))

**Why it works:**
The ? placeholder keeps user input completely separate from the SQL command.
Special characters like ' and -- are treated as plain text — not SQL code.


### Vulnerability 2 — Hardcoded Password
- **Severity:** Low
- **CWE:** CWE-259
- **Location:** Line 136
- **Bandit Rule:** B105 — hardcoded_password_string

**Vulnerable Code:**
hardcoded_password = "passwor123"

**What the attacker does:**
If they gain access to the source code or GitHub repository, 
they can see the password instantly — no hacking needed.

**Real World Impact:**
- Immediate credential exposure
- Unauthorized database access
- Full system compromise

**Fix Applied:**
secure_password = os.getenv('DB_PASSWORD', 'not_set')

**Why it works:**
The password is stored in the system's environment variables — 
completely outside the source code. Even if someone reads the code, 
they cannot see the actual password.



## 3. False Positive Identified

**Location:** Line 156
**Bandit Rule:** B105

Bandit flagged the string "not_set" as a possible hardcoded password.
This is a false positive — "not_set" is used as a default comparison 
string, not as an actual password. This highlights that automated tools 
always require human judgment alongside them.



## 4. Recommendations & Best Practices

1. Always use parameterized queries — never build SQL with f-strings or concatenation
2. Never hardcode passwords, API keys or credentials in source code
3. Store all sensitive values in environment variables or a .env file
4. Never push credentials to GitHub — use .gitignore for sensitive files
5. Run Bandit regularly as part of your development workflow
6. Always review automated scan results manually — tools can produce false positives


## 6. Conclusion

Two real vulnerabilities were successfully identified, demonstrated and fixed:
SQL Injection and Hardcoded Credentials. Both were confirmed by the Bandit 
static analyzer. The fixes applied follow industry standard secure coding 
practices and completely neutralize both attack vectors.