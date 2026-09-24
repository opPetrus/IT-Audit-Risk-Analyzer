# 🔐 IT Audit Risk Analyzer

A Python-based tool that automates IT audit checks by analyzing employee access permissions and financial transactions.

The project identifies potential control violations, calculates risk scores, classifies findings by severity, and generates an audit report.

## 🚀 Features

* 🔑 Access control analysis
* 👤 Inactive users with active access
* ⚠️ Excessive privileges
* 🔄 Segregation of Duties (SoD) conflicts
* 💰 Suspicious transactions
* 🌙 Off-hours transactions
* 📊 Risk scoring and severity classification
* 🛡️ Error handling

## 🧠 Risk Model

```text
Risk Score = Impact × Likelihood
```

| Score | Severity |
| ----: | :------- |
|   1–2 | LOW      |
|   3–4 | MEDIUM   |
|   5–6 | HIGH     |
|   7–9 | CRITICAL |

## 🛠️ Technologies

* Python
* SQL
* SQLite
* Pandas

## 📁 Structure

```text
it-audit-risk-analyzer/
├── data/
│   ├── employees.csv
│   ├── accesses.csv
│   └── transactions.csv
├── src/
│   ├── audit.py
│   └── data_loader.py
├── audit.db
└── README.md
```

## ▶️ Running

```bash
python src/data_loader.py
python src/audit.py
```

The program loads the datasets into SQLite and generates a prioritized audit report.

## 📊 Example

```text
AUDIT SUMMARY

Total Findings: 10

Critical: 5
High: 4
Medium: 1
Low: 0
```

Findings are ordered by severity and include evidence, risk score, and recommendations.

## Current Status

MVP completed.

Future improvements:
- Power BI dashboard;
- automated reporting;
- additional control tests;
