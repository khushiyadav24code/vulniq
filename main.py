from fastapi import FastAPI, Query
from pydantic import BaseModel
import json
import os

app = FastAPI()

DATA_FILE = "data/vulnerabilities.json"
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
        return json.load(file)

def save_data(data):
    os.makedirs("data", exist_ok=True)
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

@app.get("/")
def home():
    return {"project": "VulniQ", "message": "Backend Running Successfully"}

@app.post("/add")
def add_vulnerability(vuln: Vulnerability):
    data = load_data()

    normalized = {
        "id": vuln.id,
        "title": vuln.title.lower(),
        "description": vuln.description.lower(),
        "severity": vuln.severity.upper()
    }

    data.append(normalized)
    save_data(data)

    return {"message": "Vulnerability added successfully", "data": normalized}

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

    return {"query": q, "results": result}