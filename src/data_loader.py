import pandas as pd
import sqlite3 as db

conn = db.connect("audit.db")

employees = pd.read_csv("data/employees.csv")
accesses = pd.read_csv("data/accesses.csv")
transactions = pd.read_csv("data/transactions.csv")

employees.to_sql("employees", conn, if_exists="replace", index=False)
accesses.to_sql("accesses", conn, if_exists="replace", index=False)
transactions.to_sql("transactions", conn, if_exists="replace", index=False)

conn.close()