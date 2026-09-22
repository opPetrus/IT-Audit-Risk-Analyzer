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

--------------------------------------

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