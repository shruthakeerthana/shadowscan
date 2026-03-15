# 🕵️ ShadowScan

> **Automated Shadow API Discovery & Attack Simulation**

ShadowScan finds hidden API endpoints that developers forgot about, automatically attacks them to discover vulnerabilities, and generates a professional AI-powered security report — all from a clean, minimal dashboard.

---

## 🚀 What Makes ShadowScan Different

Most API security tools either **discover** or **attack**. ShadowScan does both — automatically — and then explains everything in plain English using AI.

Built for developers and security engineers who want real answers, not just a list of endpoints.

---

## ⚡ Features

- 🔎 **Shadow API Discovery** — finds undocumented & forgotten endpoints using wordlists, JS file crawling, and Swagger/OpenAPI spec detection
- 🧠 **Smart Crawling** — reads JS files to extract hidden API calls developers never documented
- 🗺️ **API Map Visualization** — interactive tree showing your entire API attack surface with severity ratings
- 💥 **Automated Attack Simulation** — tests every discovered endpoint for:
  - 🔓 Broken Authentication
  - 🪪 BOLA (Broken Object Level Authorization)
  - 📦 Excessive Data Exposure
  - 🚦 Rate Limit Bypass
  - 🏗️ Mass Assignment
- 🤖 **AI Security Report** — plain English analysis powered by Groq LLaMA 3.3 with risk levels and fix recommendations
- 📥 **Downloadable Report** — export your full security report as a text file
- 🖥️ **Clean Dashboard** — minimal dark UI with smooth scanning animation

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| Frontend | Next.js, TypeScript, Tailwind CSS |
| AI Engine | Groq LLaMA 3.3 70B |
| Security | Custom OWASP-based scanner |
| Styling | shadcn/ui components |

---

## 📦 Setup & Installation

### 1️⃣ Clone the repo
```bash
git clone https://github.com/shruthakeerthana/shadowscan.git
cd shadowscan
```

### 2️⃣ Backend Setup
```bash
pip install flask flask-cors requests groq python-dotenv beautifulsoup4
```

Create a `.env` file in the root:
```
GROQ_API_KEY=your_groq_api_key_here
```

Start the backend:
```bash
python app.py
```

Backend runs on **http://localhost:8000**

### 3️⃣ Frontend Setup
```bash
npm install
npm run dev
```

Frontend runs on **http://localhost:3000**

### 4️⃣ Start Scanning

Open **http://localhost:3000**, enter any target URL and hit **Scan**.

---

## 🖼️ How It Works
```
Enter Target URL
      ↓
JS File Crawling → finds hidden API calls in JavaScript
      ↓
Swagger Detection → extracts full endpoint map from API docs
      ↓
Endpoint Discovery → probes hundreds of common endpoints
      ↓
Attack Simulation → BOLA + Auth + Data Exposure + Rate Limit
      ↓
AI Report → plain English findings with fixes
      ↓
Visual Dashboard → API map tree + vulnerability feed
```

---

## 🧪 Practice Target

To test locally use [VAmPI](https://github.com/erev0s/VAmPI) — a deliberately vulnerable API:
```bash
docker run -d -e vulnerable=1 -p 5000:5000 erev0s/vampi:latest
```

Then scan `http://localhost:5000` — ShadowScan will find real vulnerabilities.

---

## ⚠️ Legal Disclaimer

Only scan targets you have **explicit permission** to test. ShadowScan is built for educational purposes and authorized security testing only. Unauthorized scanning is illegal.

---

## 👩‍💻 Built By

**Shrutha Keerthana** — BTech CSE-CyS @ VNR VJIET  
Cybersecurity enthusiast building tools that make security accessible.

---

⭐ If you found this useful, give it a star!
```

Save as `README.md` then:
```
git add .
git commit -m "Add README"
git push
