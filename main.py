from fastapi import UploadFile, File
from fastapi import FastAPI, Query
from pydantic import BaseModel
import json
import os

app = FastAPI()

DATA_FILE = "data/vulnerabilities.json"

# data folder create if not exists
os.makedirs("data", exist_ok=True)


class Vulnerability(BaseModel):
    id: int
    title: str
    description: str
    severity: str


def load_data():
    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as file:
        try:
            return json.load(file)
        except:
            return []


def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)


@app.get("/")
def home():
    return {
        "project": "VulniQ",
        "message": "Backend Running Successfully"
    }


@app.post("/add")
def add_vulnerability(vuln: Vulnerability):

    data = load_data()

    normalized = {
        "id": vuln.id,
        "title": vuln.title.lower(),
        "description": vuln.description.lower(),
        "severity": vuln.severity.upper()
    }

    # Duplicate Detection
    for item in data:
        if item["title"] == normalized["title"]:
            return {
                "message": "Vulnerability already exists"
            }

    data.append(normalized)
    save_data(data)

    return {
        "message": "Vulnerability added successfully",
        "data": normalized
    }


@app.get("/all")
def get_all():
    return load_data()


@app.get("/search")
def search_vulnerability(q: str = Query(...)):

    data = load_data()
    result = []

    for vuln in data:
        if q.lower() in vuln["title"] or q.lower() in vuln["description"]:
            result.append(vuln)

    return {
        "query": q,
        "results": result
    }


@app.get("/filter")
def filter_by_severity(severity: str):

    data = load_data()

    result = []

    for vuln in data:
        if vuln["severity"] == severity.upper():
            result.append(vuln)

    return result
@app.get("/attack-path")
def attack_path(vuln: str):
    name = vuln.lower()

    if "sql" in name:
        path = [
            "Input field not validated",
            "SQL Injection executed",
            "Database access gained",
            "Sensitive data leakage"
        ]
    elif "xss" in name or "cross site" in name:
        path = [
            "User input not sanitized",
            "Malicious script injected",
            "Victim browser executes script",
            "Session cookie stolen"
        ]
    else:
        path = [
            "Vulnerability found",
            "System weakness exploited",
            "Unauthorized access possible",
            "Impact on system security"
        ]

    return {
        "vulnerability": vuln,
        "attack_path": path
    }
@app.get("/filter")
def filter_by_severity(severity: str):
    data = load_data()
    result = []

    for vuln in data:
        if vuln["severity"] == severity.upper():
            result.append(vuln)

    return {
        "severity": severity.upper(),
        "results": result
    }
@app.get("/rag-search")
def rag_search(query: str):
    data = load_data()
    results = []

    query_words = query.lower().split()

    for vuln in data:
        score = 0

        text = (
            vuln["title"] + " " +
            vuln["description"] + " " +
            vuln["severity"]
        ).lower()

        for word in query_words:
            if word in text:
                score += 1

        if score > 0:
            results.append({
                "vulnerability": vuln,
                "match_score": score
            })

    results = sorted(results, key=lambda x: x["match_score"], reverse=True)

    return {
        "query": query,
        "message": "Relevant vulnerabilities found using basic RAG search",
        "results": results
    }
@app.get("/stats")
def stats():
    data = load_data()

    total = len(data)
    high = 0
    medium = 0
    low = 0

    for vuln in data:
        if vuln["severity"] == "HIGH":
            high += 1
        elif vuln["severity"] == "MEDIUM":
            medium += 1
        elif vuln["severity"] == "LOW":
            low += 1

    return {
        "total_vulnerabilities": total,
        "high": high,
        "medium": medium,
        "low": low
    }
@app.post("/upload-report")
async def upload_report(file: UploadFile = File(...)):

    content = await file.read()
    text = content.decode("utf-8")
    lower_text = text.lower()

    severity = "LOW"

    if "critical" in lower_text or "sql injection" in lower_text or "admin access" in lower_text:
        severity = "HIGH"
    elif "xss" in lower_text or "cross site scripting" in lower_text or "session cookie" in lower_text:
        severity = "MEDIUM"
    elif "low" in lower_text or "info" in lower_text:
        severity = "LOW"

    data = load_data()

    vuln = {
        "id": len(data) + 1,
        "title": "uploaded vulnerability",
        "description": lower_text,
        "severity": severity,
"attack_path": generate_attack_path(lower_text)
    }

    data.append(vuln)
    save_data(data)

    return {
        "message": "Report uploaded successfully",
        "detected_severity": severity,
        "data": vuln
    }
def generate_attack_path(text):
    lower_text = text.lower()

    if "sql injection" in lower_text or "sql" in lower_text:
        return [
            "Input validation failure",
            "SQL Injection executed",
            "Database access gained",
            "Sensitive data exposure"
        ]

    elif "xss" in lower_text or "cross site scripting" in lower_text:
        return [
            "User input not sanitized",
            "Malicious script injected",
            "Victim browser executes script",
            "Session/session cookie stolen"
        ]

    elif "weak password" in lower_text or "brute force" in lower_text:
        return [
            "Weak authentication",
            "Password guessing",
            "Account takeover",
            "Unauthorized access"
        ]

    else:
        return [
            "Vulnerability identified",
            "System weakness exploited",
            "Unauthorized action possible",
            "Security impact created"
        ]