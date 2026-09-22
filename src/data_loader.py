import pandas as pd
import sqlite3 as db

conn = db.connect("sql/audit.db")
cn = conn.cursor()

employees = pd.read_csv("data/employees.csv")
accesses = pd.read_csv("data/accesses.csv")

employees.to_sql("employees", conn, if_exists="replace", index=False)
accesses.to_sql("accesses", conn, if_exists="replace", index=False)