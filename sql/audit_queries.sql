SELECT
    employees.name,
    accesses.system,
    accesses.access_level
FROM employees
JOIN accesses
ON employees.employee_id = accesses.employee_id
WHERE employees.status = 'inactive';