from fastapi import FastAPI, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = "data/vulnerabilities.json"
USER_FILE = "users.json"
os.makedirs("data", exist_ok=True)


class Vulnerability(BaseModel):
    id: int
    title: str
    description: str
    severity: str


class User(BaseModel):
    name: str
    email: str
    password: str


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


def load_users():
    if not os.path.exists(USER_FILE):
        return []
    with open(USER_FILE, "r") as file:
        try:
            return json.load(file)
        except:
            return []


def save_users(users):
    with open(USER_FILE, "w") as file:
        json.dump(users, file, indent=4)


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
            "Session cookie stolen"
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


def generate_recommendation(text):
    lower_text = text.lower()

    if "sql injection" in lower_text or "sql" in lower_text:
        return "Use parameterized queries, validate inputs, and avoid directly concatenating user input in SQL queries."
    elif "xss" in lower_text or "cross site scripting" in lower_text:
        return "Sanitize user input, escape output, and use Content Security Policy headers."
    elif "weak password" in lower_text or "brute force" in lower_text:
        return "Enforce strong password policy, account lockout, rate limiting, and multi-factor authentication."
    else:
        return "Apply security patches, validate inputs, review configurations, and follow secure coding practices."


@app.get("/")
def home():
    return {
        "project": "VulniQ",
        "message": "Backend Running Successfully"
    }


@app.post("/add")
def add_vulnerability(vuln: Vulnerability):
    data = load_data()
    text = vuln.title + " " + vuln.description

    normalized = {
        "id": vuln.id,
        "title": vuln.title.lower(),
        "description": vuln.description.lower(),
        "severity": vuln.severity.upper(),
        "attack_path": generate_attack_path(text),
        "recommendation": generate_recommendation(text)
    }

    for item in data:
        if item["title"] == normalized["title"]:
            return {"message": "Vulnerability already exists"}

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

    return {
        "severity": severity.upper(),
        "results": result
    }


@app.get("/attack-path")
def attack_path(vuln: str):
    return {
        "vulnerability": vuln,
        "attack_path": generate_attack_path(vuln),
        "recommendation": generate_recommendation(vuln)
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
        "attack_path": generate_attack_path(lower_text),
        "recommendation": generate_recommendation(lower_text)
    }

    data.append(vuln)
    save_data(data)

    return {
        "message": "Report uploaded successfully",
        "detected_severity": severity,
        "data": vuln
    }


@app.delete("/delete/{vuln_id}")
def delete_vulnerability(vuln_id: int):
    data = load_data()
    new_data = []

    for vuln in data:
        if vuln["id"] != vuln_id:
            new_data.append(vuln)

    if len(new_data) == len(data):
        return {
            "message": "Vulnerability not found"
        }

    save_data(new_data)

    return {
        "message": "Vulnerability deleted successfully",
        "deleted_id": vuln_id
    }


@app.post("/register")
def register_user(user: User):
    users = load_users()

    for existing_user in users:
        if existing_user["email"] == user.email:
            return {
                "success": False,
                "message": "Email already registered"
            }

    new_user = {
        "name": user.name,
        "email": user.email,
        "password": user.password
    }

    users.append(new_user)
    save_users(users)

    return {
        "success": True,
        "message": "User registered successfully"
    }


@app.post("/login")
def login_user(user: User):
    users = load_users()

    for existing_user in users:
        if (
            existing_user["email"] == user.email
            and existing_user["password"] == user.password
        ):
            return {
                "success": True,
                "message": "Login successful",
                "user": {
                    "name": existing_user["name"],
                    "email": existing_user["email"]
                }
            }

    return {
        "success": False,
        "message": "Invalid email or password"
    }