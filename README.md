# Phishing Detector

## 🛡️ Overview

Phishing Detector is a Django-based web application designed to identify phishing attacks through URL and email analysis. The system helps users detect potentially malicious links and suspicious emails, improving cybersecurity awareness and protection.

The application provides individual URL scanning, email content analysis, bulk scanning capabilities, scan history management, and a personalized dashboard for users.

---

## 🚀 Features

* URL Phishing Detection
* Email Phishing Detection
* Bulk URL Scanning
* User Dashboard
* Scan History Tracking
* User Profile Management
* Authentication and User Accounts
* Real-time Analysis and Results
* Responsive Web Interface

---

## 🛠️ Technologies Used

### Backend

* Python
* Django
* SQLite3

### Frontend

* HTML
* CSS
* JavaScript
* Django Templates

### Security & Analysis

* URL Feature Extraction
* Email Content Analysis
* Phishing Detection Algorithms

---

## 📂 Project Structure

```text
PHISHING_DETECTOR/
│
├── detector/
│   ├── migrations/
│   ├── templates/
│   │   └── detector/
│   │       ├── index.html
│   │       ├── dashboard.html
│   │       ├── email_scan.html
│   │       ├── bulk_scan.html
│   │       ├── history.html
│   │       └── profile.html
│   │
│   ├── admin.py
│   ├── analyzer.py
│   ├── apps.py
│   ├── email_scanner.py
│   ├── models.py
│   ├── tests.py
│   ├── urls.py
│   └── views.py
│
├── phishing_detector/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── db.sqlite3
├── manage.py
├── requirements.txt
├── .env
└── .gitignore
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/agent47-alt/phishing-detector.git
cd phishing-detector
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### 3. Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Apply Database Migrations

```bash
python manage.py migrate
```

### 6. Run the Server

```bash
python manage.py runserver
```

### 7. Open in Browser

```text
http://127.0.0.1:8000/
```

---

## 🔍 How It Works

### URL Scanning

Users submit a URL, and the system analyzes various characteristics associated with phishing websites to determine whether the URL is safe or suspicious.

### Email Scanning

Users can submit email content for analysis. The system checks for phishing indicators such as suspicious links, sender patterns, and malicious content.

### Bulk Scanning

Multiple URLs can be scanned simultaneously, making large-scale analysis efficient and time-saving.

### Dashboard

The dashboard provides an overview of scans, user activity, and historical results.

---

## 📈 Future Enhancements

* Machine Learning Based Detection
* Browser Extension Integration
* Real-time Threat Intelligence API
* Advanced Reporting System
* PDF Report Generation
* Email Attachment Analysis
* Multi-user Role Management

---

## 👨‍💻 Contributors

* Athul Krishna

---

## 📜 License

This project is intended for educational and research purposes.
