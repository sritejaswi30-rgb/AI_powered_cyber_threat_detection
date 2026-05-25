# AI-Powered Cyber Threat Detection System

An intelligent cybersecurity monitoring system that uses Machine Learning and AI-based anomaly detection to identify malicious network activity and suspicious behavior in real time.

---

## 🚀 Project Overview

This project analyzes network traffic data and detects cyber threats using:
- Machine Learning classification
- Deep Learning anomaly detection
- Real-time monitoring dashboard
- Interactive data visualization

The system simulates a Security Operations Center (SOC) dashboard capable of identifying both known and unknown cyber attacks.

---

## 🛡️ Features

- Upload cybersecurity datasets
- Data preprocessing and normalization
- Attack classification using Random Forest
- AI anomaly detection using Autoencoder Neural Network
- Real-time cyber threat alerts
- Threat severity classification
- Interactive dashboard and charts
- Live monitoring panel
- Downloadable threat reports
- Modern dark cybersecurity UI

---

## 🧠 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| pandas | Data processing |
| scikit-learn | Machine learning models |
| TensorFlow/Keras | Deep learning autoencoder |
| Streamlit | Interactive dashboard |
| matplotlib | Data visualization |
| seaborn | Statistical plotting |
| Plotly | Interactive charts |

---

## 📂 Dataset

This project uses public cybersecurity datasets:
- UNSW-NB15
- CICIDS2017

Dataset contains:
- packet size
- protocol
- source IP
- destination IP
- connection duration
- attack labels
- network traffic statistics

---

## ⚙️ Project Workflow

```text
Dataset Collection
        ↓
Data Cleaning & Preprocessing
        ↓
Feature Engineering
        ↓
Machine Learning Training
        ↓
AI Anomaly Detection
        ↓
Threat Prediction
        ↓
Dashboard Visualization & Alerts
```

---

## 🤖 Machine Learning Models

### 1. Random Forest Classifier
Used for:
- attack classification
- malicious traffic prediction
- supervised learning detection

### 2. Isolation Forest
Used for:
- anomaly detection
- suspicious traffic identification

### 3. Autoencoder Neural Network

Purpose:
- learn normal traffic behavior
- detect unknown cyber attacks
- identify abnormal patterns

---

## 📊 Dashboard Features

Dashboard includes:
- Real-time threat monitoring
- Attack statistics
- Anomaly score visualization
- Threat severity indicators
- Traffic analysis charts
- Interactive graphs
- Security alerts panel
- Live network activity simulation

---

## 🚨 Threat Alert System

The application provides:
- Critical threat alerts
- Suspicious activity warnings
- Threat severity levels
- Live attack counter
- Timestamped alert history

Severity Levels:
- Low
- Medium
- High
- Critical

---

## 📁 Project Structure

```text
AI-Cyber-Threat-Detection/
│
├── app.py
├── train_model.py
├── requirements.txt
├── README.md
├── dataset/
│   └── UNSW_NB15.csv
│
├── models/
│   ├── random_forest.pkl
│   ├── isolation_forest.pkl
│   └── autoencoder.h5
│
├── assets/
│
└── reports/
```

---

## ▶️ Installation

Clone the repository:

```bash
git clone <your-github-repo>
cd AI-Cyber-Threat-Detection
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Project

### Train the models

```bash
python train_model.py
```

### Start the dashboard

```bash
streamlit run app.py
```

Open browser:

```text
http://localhost:8501
```

---

## 📈 Sample Visualizations

The dashboard displays:
- attack distribution charts
- anomaly score graphs
- confusion matrix heatmaps
- live traffic analytics
- packet behavior trends

---

## 🔍 Real-World Applications

This project can be applied in:
- enterprise security monitoring
- SOC environments
- banking cybersecurity
- cloud infrastructure monitoring
- intrusion detection systems
- threat intelligence platforms

---

## 🚀 Future Improvements

Possible enhancements:
- real-time packet sniffing using Scapy
- cloud deployment
- email/SMS alerts
- explainable AI (XAI)
- advanced deep learning models
- Docker deployment

---

## 💼 Resume Description

Built an AI-Powered Cyber Threat Detection System using Machine Learning and Deep Learning models to analyze network traffic, detect anomalies, and visualize cyber threats through an interactive Streamlit dashboard.

---

## 👨‍💻 Author

Your Name Here

---

## 📜 License

This project is for educational and research purposes.
