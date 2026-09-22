import pandas as pd

employees = pd.read_csv("data/employees.csv")
accesses = pd.read_csv("data/accesses.csv")

print("Employees:")
print(employees)

print("\nAccesses:")
print(accesses)