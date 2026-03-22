# SQL Injection Detection & Prevention System (SQL Guardian)

🔐 **Built for Security Engineering Portfolio**

This project is a high-performance web application designed to detect, log, and prevent SQL Injection (SQLi) attacks. It demonstrates advanced security patterns including heuristic anomaly detection, input sanitization, and parameterized queries.

## 🚀 Key Features
- **🔍 Real-time Detection**: Identifies SQLi patterns (e.g., `' OR 1=1 --`) using regex-based heuristic analysis.
- **🛡️ Multi-Layer Prevention**:
  - **Parameterized Queries**: Eliminates logic poisoning at the database level.
  - **Input Sanitization**: Filters malicious payloads using custom validation filters.
- **📊 Attack Intelligence Hub**: Admin dashboard with real-time visualization of threat vectors using **Chart.js**.
- **🚫 Automated IP Firewall**: Dynamically blocks malicious IPs after repeated attack attempts (3-strike policy).
- **📋 Live Logging**: Tracks every suspicious request, IP address, and payload for forensic analysis.

## 🛠️ Tech Stack
- **Backend**: Python (Flask)
- **Database**: SQLite3 / SQLAlchemy ORM
- **Frontend**: HTML5, Modern CSS (Glassmorphism), JavaScript
- **Visualization**: Chart.js
- **Icons**: Lucide Icons
- **Security Concepts**: OWASP Top 10, Parameterized Queries, Heuristic Analysis, IP Filtering.

## 📂 Project Structure
```bash
sql-injection-detector/
│
├── app.py              # Main Flask application & routes
├── requirements.txt    # Project dependencies
├── database/           # SQLite database storage
├── logs/               # Attack history & audit logs
├── utils/
│   ├── validator.py    # Input sanitization & validation logic
│   └── detector.py     # SQLi pattern matching engine
├── templates/          # Modern UI templates (JinJa2)
└── static/             # Assets (CSS/JS)
```

## 🏗️ Getting Started
1. Clone the repository:
```bash
git clone https://github.com/anishkumar79/EventStar.git
cd SQLi
```
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the application:
```bash
python app.py
```
4. Access the dashboard: `http://localhost:8000/`

## 🧪 Demonstration Steps
1. **Navigate to "Vulnerable Lab"**: Try basic bypasses like `' OR 1=1 --`. Notice how the system returns unauthorized data.
2. **Navigate to "Secure Engine"**: Attempt the same bypass. The system will detect the anomaly, block the action, and log it.
3. **Visit "Admin Dashboard"**: View the pie chart of attack vectors and the list of logged attempts. Repeated attacks will result in your IP being blocked.

## 🛡️ OWASP Alignment
This project directly addresses **A03:2021 – Injection**, the number three risk on the OWASP Top 10, by implementing industry-standard remediation techniques.
