import sqlite3 as db

conn = db.connect("audit.db")

def calculate_risk_score(impact, likelihood):
    return impact * likelihood


def get_severity(score):
    if score >= 7:
        return "CRITICAL"
    elif score >= 5:
            return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"
    

def detect_intern_admin(conn):

    query = """
    SELECT
        e.employee_id,
        e.name,
        e.role,
        e.status,
        a.system,
        a.access_level
    FROM employees e
    JOIN accesses a
        ON e.employee_id = a.employee_id
    WHERE a.access_level = 'admin'
      AND e.role = 'Intern' 
      AND e.status = 'active';
    """

    result = conn.execute(query)
    
    impact = 3
    likelihood = 2
    risk_score = calculate_risk_score(impact, likelihood)
    severity = get_severity(risk_score)

    findings = []

    for row in result:
        finding = {
            "employee_id": row[0],
            "employee_name": row[1],
            "risk_type": "Excessive privilege",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"Role: {row[2]}, Status: {row[3]}, System: {row[4]}, Access: {row[5]}",
            "recommendation": "Review and reduce the employee's access privileges."
        }

        findings.append(finding)

    return findings


def detect_inactive_access(conn):

    query = """
    SELECT
        e.employee_id,
        e.name,
        e.status,
        a.system,
        a.access_level
    FROM employees e
    JOIN accesses a
        ON e.employee_id = a.employee_id
    WHERE e.status = 'inactive';
    """

    result = conn.execute(query)

    impact = 3
    likelihood = 3
    risk_score = calculate_risk_score(impact, likelihood)
    severity = get_severity(risk_score)

    findings = []

    for row in result:
        finding = {
            "employee_id": row[0],
            "employee_name": row[1],
            "risk_type": "Inactive Access",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"Status: {row[2]}, System: {row[3]}, Access: {row[4]}",
            "recommendation": "Review and revoke the employee's access privileges."
        }

        findings.append(finding)

    return findings


def detect_excessive_access(conn):

    query = """
    SELECT
        e.employee_id,
        e.name,
        e.status,
        e.role,
        COUNT(*)
    FROM employees e
    JOIN accesses a
        ON e.employee_id = a.employee_id
    WHERE e.status = 'active'
    GROUP BY e.employee_id, e.name, e.status, e.role
    HAVING COUNT(*) > 2;
    """

    result = conn.execute(query)

    impact = 2
    likelihood = 2
    risk_score = calculate_risk_score(impact, likelihood)
    severity = get_severity(risk_score)

    findings = []

    for row in result:
        finding = {
            "employee_id": row[0],
            "employee_name": row[1],
            "risk_type": "Excessive Access",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"Status: {row[2]}, Role: {row[3]}, Number of Accesses: {row[4]}",
            "recommendation": "Review and reduce the employee's access privileges."
        }

        findings.append(finding)

    return findings

def run_audit(conn):
    findings = []

    findings.extend(detect_intern_admin(conn))
    findings.extend(detect_inactive_access(conn))
    findings.extend(detect_excessive_access(conn))

    return findings


def print_report(findings):
    print("\n" + "=" * 50)
    print("IT AUDIT RISK ANALYZER")
    print("=" * 50)

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['risk_type']}")
        print(f"Employee: {finding['employee_name']}")
        print(f"Risk Score: {finding['risk_score']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Recommendation: {finding['recommendation']}")

    print("\n" + "=" * 50)
    print(f"{len(findings)} risk(s) detected")
    print("=" * 50 + "\n")


findings = run_audit(conn)

print_report(findings)

conn.close()