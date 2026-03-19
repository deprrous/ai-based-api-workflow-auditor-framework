# Project Context: Full-Stack Agentic AI API Auditing System

## 1. Project Vision
We are building an autonomous "Agentic AI" cybersecurity platform that audits APIs for complex Business Logic vulnerabilities (e.g., BOLA, IDOR). 
Crucially, the system must include a **User-Friendly Web Client** designed for "non-security guys" (developers, product managers). It must visually map the API workflows and explain vulnerabilities in plain English with actionable, copy-paste code fixes, bridging the gap between deep cybersecurity logic and everyday software development.

## 2. Tech Stack & Infrastructure
* **Backend & AI Engine:** Python, FastAPI, Pydantic, SQLAlchemy, PostgreSQL, and a custom provider-neutral ReAct loop for LLM orchestration.
* **Traffic Capture:** `mitmproxy` for live HTTP traffic capture and replay preparation.
* **Frontend (Web Client):** Next.js, React, TypeScript, and **React Flow** for workflow visualization.
* **Styling & Realtime:** Custom CSS design system for the dashboard and SSE for live scan updates.

## 3. Data Ingestion Layer (The 4 Pillars)
The AI Orchestrator requires "Data Fusion" from 4 sources:
1.  **Live HTTP Traffic (Proxy):** Intercepted requests/responses.
2.  **Source Code (White-box):** Ingested backend code snippets.
3.  **API Specification:** Swagger/OpenAPI docs.
4.  **Knowledge Base:** Security rules mapping to OWASP API Top 10.

## 4. Frontend Web Client Features (For Non-Security Users)
The client-side dashboard must focus on usability and visualization:
* **Interactive Workflow Mapping:** A visual, node-based graph (using React Flow) showing how APIs interact. E.g., `[POST /login]` -> `[GET /user/profile]`. The nodes should light up red if the AI detects a logic break in that specific path.
* **Plain-English Risk Scoring:** Instead of complex CVSS metrics, use intuitive health scores (e.g., "Critical: Data Leak Risk", "Safe").
* **Developer-Friendly Remediation:** Vulnerability reports must explain *why* it's broken in developer terms and provide direct, copy-paste code patches.
* **Scan Trigger & Real-time Logs:** A simple button to "Start Audit" and a feed showing what the AI Agent is currently "thinking" and "testing" in real-time.

## 5. System Architecture: The ReAct Loop
1. **Reason:** The LLM correlates Swagger docs with live traffic to form hypotheses.
2. **Act:** The Agent calls the **Workflow Mapper** (which feeds data to the Frontend UI) and the **Automated Verifier** to generate Python PoC scripts.
3. **Observe:** The system executes the PoC. If successful, it sends the confirmed vulnerability and the auto-patch to the Frontend Dashboard.

## 6. Core Modules to Develop
Please organize the codebase into this modular full-stack structure:
1.  `backend/ai_orchestrator/`: The ReAct agent loop.
2.  `backend/proxy_engine/`: Captures traffic and formats it.
3.  `backend/tools/`: `semantic_analyzer.py` and `verifier.py` (PoC execution).
4.  `backend/api_server/`: FastAPI endpoints to serve data to the frontend.
5.  `frontend_client/`: React/Next.js application containing the Dashboard, Workflow Visualizer (React Flow), and Report Viewer.

## 7. OpenCode & Execution Features
* **OpenCode Integration:** Feel free to leverage OpenCode features or relevant open-source libraries (e.g., React Flow, Mitmproxy) to accelerate development.
* If the environment supports it, use code execution/sandbox features to test the backend logic or UI components before finalizing the code.

## Instructions for the AI Agent
Based on this context, your first task is to set up the foundational repository structure. 
1. Initialize the `backend` with a basic FastAPI app.
2. Initialize the `frontend_client` (React) and create a basic layout for the Dashboard that includes a placeholder area for the "API Workflow Visualization" graph.
We will implement the LLM ReAct loop and Proxy step-by-step later.
