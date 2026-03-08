# Email Security Audit Tool

A Python-based tool to audit a domain's email security configuration by checking **SPF, DKIM, and DMARC DNS records**.
This helps identify potential **email spoofing vulnerabilities** and misconfigured email authentication policies.

## 📌 Features

* Checks **DMARC** record and extracts policy (`none`, `quarantine`, `reject`)
* Checks **SPF** record and warns if it is overly permissive
* Checks **DKIM** record using given selectors
* Displays results in a **clean terminal table**
* Calculates an **Email Security Score**
* Optional **JSON export of scan results**
* Interactive CLI for scanning multiple domains

---

## 🛠 Technologies Used

* **Python 3**
* `dnspython` – DNS queries
* `rich` – Beautiful CLI output tables
* `json` – Export scan results

---

## 📂 Project Structure

```
email-security-audit-tool
│
├── email_security_audit.py
├── requirements.txt
├── README.md
└── docs
    ├── Capstone Phase 1 Final Report.pdf
    ├── Capstone Review 1 PPT.pdf
    ├── Capstone Review 2 outline.docx
    └── Capstone_Research Papers.docx
```

---

## ⚙️ Installation

Clone the repository:

```
git clone https://github.com/YOUR_USERNAME/email-security-audit-tool.git
cd email-security-audit-tool
```

Install required dependencies:

```
pip install -r requirements.txt
```

or

```
pip install rich dnspython
```

---

## ▶️ Usage

Run the tool:

```
python email_security_audit.py
```

Example interaction:

```
Enter a domain (or type 'exit' to quit): google.com
Enter DKIM selectors separated by space (press Enter for 'default'):
Do you want to export results to JSON? (y/n): y
```

The tool will display:

* DMARC status
* SPF record details
* DKIM selector result
* Overall email security score

---

## 📊 Example Output

```
Email Security Audit for google.com

Record   Status   Details
DMARC    Exists   Policy: reject
SPF      Exists   v=spf1 include:_spf.google.com ~all
DKIM     Exists   Selector: default

Overall Email Security Score: 3/3
```

---

## 🎯 Use Cases

* Detect **email spoofing vulnerabilities**
* Verify **domain email authentication configuration**
* Perform **basic email security auditing**
* Educational use in **cybersecurity projects**

---

## 🚀 Future Improvements

* MX record analysis
* Email spoofing risk detection
* DNSSEC validation
* Web dashboard interface
* Automated security scoring system

---

## 👨‍💻 Author

**Kiran Kumar. Ch**
B.Tech Cyber Security

---

## 📜 License

This project is for **educational and research purposes**.
