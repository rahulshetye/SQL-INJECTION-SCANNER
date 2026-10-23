# 🛡️ VulnScan Pro – Advanced SQL Injection Scanner

VulnScan Pro is a Python-based **Flask web application** designed to detect SQL Injection vulnerabilities in web applications using multiple testing techniques and intelligent analysis.

It simulates real-world vulnerability assessment approaches by injecting crafted SQL payloads into URL parameters and evaluating server responses.

---

## 📌 Key Highlights

- Multi-technique SQL Injection detection  
- Automatic parameter extraction from URLs  
- Intelligent response analysis  
- Risk scoring system (0–100)  
- REST API-based architecture  
- Web-based user interface  

---

## 🚀 Features

### 🔍 SQL Injection Detection Techniques
- **Error-Based SQL Injection**
- **Time-Based Blind SQL Injection**
- **Union-Based SQL Injection**

---

### ⚙️ Scanning Capabilities
- Automatic extraction of query parameters from target URLs  
- Injection of payloads into each parameter individually  
- Supports both **GET** and **POST** requests  
- Categorized payload execution based on attack type  

---

### 🧠 Detection Mechanism

The scanner identifies vulnerabilities using:

- **Error Keyword Matching**  
  Detects database-related error messages in responses  

- **Response Length Analysis**  
  Compares baseline and injected responses  

- **Time Delay Detection**  
  Identifies abnormal delays caused by time-based payloads  

---

### 📊 Risk Scoring System

The tool assigns a **risk score (0–100)** based on detection confidence:

| Score Range | Severity  |
|------------|----------|
| 70–100     | CRITICAL |
| 40–69      | HIGH     |
| 20–39      | MEDIUM   |
| 1–19       | LOW      |
| 0          | SAFE     |

---

### 📁 API Endpoints

| Endpoint   | Method | Description |
|-----------|--------|-------------|
| /scan     | POST   | Performs vulnerability scan |
| /export   | POST   | Returns structured JSON report |

---

## 🧱 Architecture

- **Backend:** Flask (Python)
- **Frontend:** HTML, CSS, JavaScript (served via `/static`)
- **Core Engine:** Python (`requests`, `urllib`, parsing modules)

---

## 📂 Project Structure

```bash
sql-injection-scanner/
│
├── scanner_gui.py        # Flask backend + scanning engine
├── static/               # Frontend UI files
├── requirements.txt      # Dependencies
└── README.md
```

---

## 🧠 How It Works

1. User inputs a target URL through the web interface  
2. Application extracts query parameters automatically  
3. A baseline request is sent to capture normal response behavior  
4. SQL payloads are injected into each parameter  
5. Responses are analyzed based on:
   - Error messages  
   - Response size variation  
   - Response time anomalies  
6. Results are compiled and assigned a **risk score and severity level**  

---

## ▶️ Installation

```bash
git clone https://github.com/Aryan457-dev/sql-injection-scanner.git
cd sql-injection-scanner
pip3 install -r requirements.txt
```

---

## ▶️ Usage

```bash
python3 scanner_gui.py
```

Open your browser and navigate to:

```
http://localhost:5122
```

---

## 🧪 Example Output

```json
{
  "risk_score": 75,
  "risk_label": "CRITICAL",
  "vulnerable_count": 12,
  "total_tests": 45
}
```

---

## ⚠️ Limitations

- Supports only single URL scanning (no crawler)  
- No authentication/session handling  
- Limited blind SQL Injection detection (time-based only)  
- May produce false positives  
- No WAF bypass techniques  

---

## 🔮 Future Enhancements

- Full website crawling  
- Boolean-based blind SQL Injection detection  
- Multi-threaded scanning for performance  
- Export reports in PDF/HTML format  
- WAF evasion techniques  
- Advanced payload customization  

---

## ⚠️ Disclaimer

This tool is intended strictly for **educational purposes and authorized security testing only**.  
Unauthorized scanning of systems is illegal.

---

## 👨‍💻 Author

**Rahul Shetye** 
Cybersecurity Enthusiast  

---

## 🤝 Contribution

Contributions are welcome.  
Feel free to fork this repository and submit pull requests.

---
