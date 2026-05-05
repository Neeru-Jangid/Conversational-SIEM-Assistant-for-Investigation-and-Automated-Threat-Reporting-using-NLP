# Conversational-SIEM-Assistant-for-Investigation-and-Automated-Threat-Reporting-using-NLP

## 📌 Overview

This project is an end-to-end AI-driven security analytics system that converts natural language queries into actionable SIEM insights.

It combines **LLMs, Retrieval-Augmented Generation (RAG), and OpenSearch** to enable users to interact with security data using plain English and receive structured reports with visualizations and narratives.

---

## ⚙️ Key Features

* 🧠 **Intent Classification (LLM-based)**
  Detects user intent and extracts entities (IP, user, severity, etc.)

* 🔍 **RAG for Context Retrieval**
  Retrieves relevant schema fields to improve query generation accuracy

* 🧾 **DSL Query Generation**
  Converts natural language → OpenSearch queries using LLMs

* ✅ **Validation + Fallback System**
  Ensures robustness with template-based query recovery

* ⚡ **In-Memory Filtering for Follow-ups**
  Optimizes performance by avoiding redundant queries

* 📊 **Automated Reporting**
  Generates:

  * Tables
  * Charts
  * pdf & word doc

* 🧠 **Conversation Memory**
  Supports multi-turn queries and contextual understanding

---

## 🏗️ Architecture

User Input
→ Intent Classification (LLM)
→ RAG (Schema Retrieval)
→ DSL Generation
→ Validation / Fallback
→ SIEM Query Execution (OpenSearch)
→ Report Generation (Charts + Narrative)
→ Memory Update

---

## 📂 Project Structure

```
├── pipeline.py        # Main orchestrator (core logic)
├── engine/            # Processing + validation logic
├── llm/               # LLM interactions (classification, generation)
├── rag/               # Retrieval system (schema/context)
├── memory/            # Conversation state handling
├── siem/              # SIEM/OpenSearch connector
├── reports/           # Report generation (tables, charts, narratives)
├── config/            # Configuration files
├── data/              # Input datasets / logs
├── ui/                # Frontend (if applicable)
├── tests/             # Testing modules
├── requirements.txt   # Dependencies
└── docker-compose.yml # Deployment setup
```

---

## 🧪 Example Query

```
"Show failed login attempts in the last 24 hours"
```

### Output:

* Structured results (logs)
* Aggregations (counts, trends)
* Visualization (charts)
* Narrative summary

---

## 🛠️ Tech Stack

* **Python**
* **LLMs (Llama 3.1 / Ollama)**
* **OpenSearch / SIEM**
* **RAG Architecture**
* **Docker (optional deployment)**

---

## 🚀 Getting Started

### 1. Clone the repository

```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file and add required keys:

```
OPENAI_API_KEY=your_key
SIEM_ENDPOINT=your_endpoint
```

### 4. Run the pipeline

```
python pipeline.py
```

---

## 📈 Future Improvements

* Real-time streaming support
* Advanced anomaly detection
* Role-based access control
* Dashboard enhancements

---

## 🤝 Contributors

* Your Name
* Your Friend's Name

---

## 📄 License

This project is for academic and demonstration purposes.
