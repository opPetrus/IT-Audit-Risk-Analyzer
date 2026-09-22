import sqlite3 as db

conn = db.connect("audit.db")

query = """
SELECT
    e.employee_id,
    e.name,
    e.role,
    a.system,
    a.access_level
FROM employees e
JOIN accesses a
    ON e.employee_id = a.employee_id
WHERE a.access_level = 'admin'
AND e.role = 'Intern';
"""

result = conn.execute(query)

for row in result:
    print(row)

conn.close()