import sqlite3 as db

def connect_database():
    try:
        conn = db.connect("audit.db")
        return conn
    except db.Error as e:
        print(f"Database error: {e}")
        return None

conn = connect_database()


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


def detect_sod_conflicts(conn):
    query = """
    SELECT
        e.employee_id,
        e.name,
        COUNT(DISTINCT a.system)
    FROM employees e
    JOIN accesses a
        ON a.employee_id = e.employee_id
    WHERE e.status = 'active'
    AND a.access_level = 'admin'
    AND (
        a.system = 'ERP'
        OR a.system = 'Bank_Portal'
    )
    GROUP BY e.employee_id, e.name
    HAVING COUNT(DISTINCT a.system) = 2;
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
            "risk_type": "SOD Conflict",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"ERP/admin + Bank_Portal/admin ({row[2]} conflicting accesses)",
            "recommendation": "Review and reduce the employee's access privileges."
        }

        findings.append(finding)

    return findings


def detect_suspicious_transactions(conn):
    query = """
    SELECT 
        e.employee_id,
        e.name,
        t.transaction_id,
        t.amount,
        t.transaction_type,
        t.approved
    FROM employees e
    JOIN transactions t
        ON e.employee_id = t.employee_id
    WHERE t.amount > 10000
    AND t.approved = 0;
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
            "transaction_id": row[2],
            "risk_type": "Suspicious Transaction",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"Amount: {row[3]}, Type: {row[4]}, Approved: {row[5]}",
            "recommendation": "Investigate the suspicious transaction and take appropriate action."
        }

        findings.append(finding)

    return findings


def detect_off_hours_transactions(conn):
    query = """
    SELECT
        e.employee_id,
        e.name,
        t.transaction_id,
        t.amount,
        t.transaction_type,
        t.timestamp,
        t.approved
    FROM employees e
    JOIN transactions t
        ON e.employee_id = t.employee_id
    WHERE strftime('%H:%M', t.timestamp) BETWEEN '00:00' AND '05:59'
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
            "transaction_id": row[2],
            "timestamp": row[5],
            "risk_type": "Off-Hours Transaction",
            "impact": impact,
            "likelihood": likelihood,
            "risk_score": risk_score,
            "severity": severity,
            "evidence": f"Amount: {row[3]}, Type: {row[4]}, Approved: {row[6]}",
            "recommendation": "Review the transaction and verify whether the timing was authorized."
        }

        findings.append(finding)

    return findings


def run_audit(conn):
    try:
        findings = []

        findings.extend(detect_intern_admin(conn))
        findings.extend(detect_inactive_access(conn))
        findings.extend(detect_excessive_access(conn))
        findings.extend(detect_sod_conflicts(conn))
        findings.extend(detect_suspicious_transactions(conn))
        findings.extend(detect_off_hours_transactions(conn))

        return findings

    except db.Error as e:
        print(f"Audit error: {e}")
        return None


def print_report(findings):
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)

    print(f"\nTotal Findings: {len(findings)}")

    critical = 0
    high = 0
    medium = 0
    low = 0

    for finding in findings:
        if finding['severity'] == 'CRITICAL':
            critical += 1
        elif finding['severity'] == 'HIGH':
            high += 1
        elif finding['severity'] == 'MEDIUM':
            medium += 1
        elif finding['severity'] == 'LOW':  
            low += 1

    print(f"\nCritical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}")

    print("\n" + "=" * 60)
    print("AUDIT FINDINGS")
    print("=" * 60)

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    findings = sorted(
        findings,
        key=lambda finding: severity_order[finding["severity"]]
    )

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['risk_type']}")
        print(f"Employee: {finding['employee_name']}")
        if 'transaction_id' in finding:
            print(f"Transaction ID: {finding['transaction_id']}")
        if 'timestamp' in finding:
            print(f"Timestamp: {finding['timestamp']}")
        print(f"Risk Score: {finding['risk_score']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Recommendation: {finding['recommendation']}")

    print("\n" + "=" * 60 + "\n")


if conn:
    findings = run_audit(conn)
    if findings is not None:
        print_report(findings)
    conn.close()