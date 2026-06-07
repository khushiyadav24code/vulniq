const API_URL = "http://127.0.0.1:8000";

let searchedIds = [];
let riskChart = null;

window.onload = function () {
    setupDarkMode();

    if (localStorage.getItem("loggedIn") === "true") {
        showDashboard();
    } else {
        showLogin();
    }
};

function showDashboard() {
    document.getElementById("loginPage").style.display = "none";
    document.getElementById("dashboard").style.display = "block";
    const name = localStorage.getItem("userName") || "User";
    document.getElementById("userProfile").innerText = `Welcome ${name}`;
    getStats();
    loadAll();
}

function showLogin() {
    document.getElementById("loginPage").style.display = "flex";
    document.getElementById("dashboard").style.display = "none";
}

async function registerUser() {
    const name = document.getElementById("regName").value;
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const message = document.getElementById("loginMessage");

    if (!name || !email || !password) {
        message.innerText = "Please fill all fields";
        return;
    }

    const response = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password })
    });

    const data = await response.json();
    message.innerText = data.message;
}

async function loginUser() {
    const name = document.getElementById("regName").value || "User";
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const message = document.getElementById("loginMessage");

    if (!email || !password) {
        message.innerText = "Please enter email and password";
        return;
    }

    const response = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password })
    });

    const data = await response.json();

    if (data.success) {
        localStorage.setItem("loggedIn", "true");
        localStorage.setItem("userEmail", email);
        localStorage.setItem("userName", data.user.name);
        showDashboard();
    } else {
        message.innerText = data.message;
    }
}

function logoutUser() {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("userName");

    document.getElementById("loginEmail").value = "";
    document.getElementById("loginPassword").value = "";
    document.getElementById("regName").value = "";
    document.getElementById("loginMessage").innerText = "Logged out successfully";

    showLogin();
}

async function addVulnerability() {
    const title = document.getElementById("vulnTitle").value;
    const description = document.getElementById("vulnDescription").value;
    const severity = document.getElementById("vulnSeverity").value;

    if (!title || !description) {
        alert("Please fill title and description");
        return;
    }

    const payload = {
        id: Date.now(),
        title,
        description,
        severity
    };

    const response = await fetch(`${API_URL}/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    const data = await response.json();

    showResult(data);
    getStats();
    loadAll();

    document.getElementById("vulnTitle").value = "";
    document.getElementById("vulnDescription").value = "";
}

async function uploadReport() {
    const fileInput = document.getElementById("reportFile");
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select a report file");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${API_URL}/upload-report`, {
        method: "POST",
        body: formData
    });

    const data = await response.json();

    showResult(data);
    getStats();
    loadAll();

    fileInput.value = "";
}

async function searchVuln() {
    const query = document.getElementById("searchQuery").value;

    if (!query) {
        alert("Please enter search text");
        return;
    }

    const response = await fetch(`${API_URL}/rag-search?query=${encodeURIComponent(query)}`);
    const data = await response.json();

    searchedIds = data.results.map(item => item.vulnerability.id);

    showResult(data);
    loadAll();
}

async function filterSeverity() {
    const severity = document.getElementById("filterSeverity").value;

    const response = await fetch(`${API_URL}/filter?severity=${severity}`);
    const data = await response.json();

    showResult(data);
}

async function getStats() {
    const response = await fetch(`${API_URL}/stats`);
    const data = await response.json();

    document.getElementById("total").innerText = data.total_vulnerabilities;
    document.getElementById("high").innerText = data.high;
    document.getElementById("medium").innerText = data.medium;
    document.getElementById("low").innerText = data.low;

    if (typeof Chart !== "undefined") {
        drawChart(data.high, data.medium, data.low);
    }
}

let chartInstance = null;

function drawChart(high, medium, low) {

    const ctx =
        document.getElementById("riskChart");

    if (chartInstance) {
        chartInstance.destroy();
    }

    chartInstance = new Chart(ctx, {
        type: "pie",
        data: {
            labels: [
                "High Risk",
                "Medium Risk",
                "Low Risk"
            ],
            datasets: [{
                data: [
                    high,
                    medium,
                    low
                ],
                backgroundColor: [
                    "#dc2626",
                    "#f59e0b",
                    "#16a34a"
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "bottom"
                }
            }
        }
    });
}

async function loadAll() {
    const response = await fetch(`${API_URL}/all`);
    const data = await response.json();

    const list = document.getElementById("vulnList");
    list.innerHTML = "";

    data.forEach(vuln => {
        const div = document.createElement("div");

        div.className = searchedIds.includes(vuln.id)
            ? "vuln-item highlight"
            : "vuln-item";

        div.innerHTML = `
            <h3>${vuln.title}</h3>

            <span class="badge ${vuln.severity}">
                ${vuln.severity}
            </span>

            <p>${vuln.description}</p>

            <div class="attack-section">
                <h4>Attack Path</h4>
                ${
                    vuln.attack_path && vuln.attack_path.length > 0
                    ? `<ol>${vuln.attack_path.map(step => `<li>${step}</li>`).join("")}</ol>`
                    : `<p class="empty">No attack path available</p>`
                }
            </div>

            <div class="recommendation-section">
                <h4>Recommendation</h4>
                <p>${vuln.recommendation || "No recommendation available"}</p>
            </div>

            <button class="delete-btn" onclick="deleteVulnerability(${vuln.id})">
                Delete
            </button>
        `;

        list.appendChild(div);
    });
}

async function deleteVulnerability(id) {
    if (!confirm("Delete this vulnerability?")) {
        return;
    }

    const response = await fetch(`${API_URL}/delete/${id}`, {
        method: "DELETE"
    });

    const data = await response.json();

    showResult(data);
    getStats();
    loadAll();
}

async function downloadReport() {
    const response = await fetch(`${API_URL}/all`);
    const data = await response.json();

    const fileData = JSON.stringify(data, null, 2);
    const blob = new Blob([fileData], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "vulniq_report.json";
    a.click();

    URL.revokeObjectURL(url);
}

async function downloadPDFReport() {
    const response = await fetch(`${API_URL}/all`);
    const vulnerabilities = await response.json();

    const statsResponse = await fetch(`${API_URL}/stats`);
    const stats = await statsResponse.json();

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    doc.setFontSize(18);
    doc.text("VulniQ Security Report", 20, 20);

    doc.setFontSize(11);
    doc.text("Centralized Vulnerability Detection and Intelligent Query Interface", 20, 30);

    doc.setFontSize(13);
    doc.text(`Total Vulnerabilities: ${stats.total_vulnerabilities}`, 20, 45);
    doc.text(`High Risk: ${stats.high}`, 20, 55);
    doc.text(`Medium Risk: ${stats.medium}`, 20, 65);
    doc.text(`Low Risk: ${stats.low}`, 20, 75);

    let y = 95;

    vulnerabilities.forEach((vuln, index) => {
        if (y > 260) {
            doc.addPage();
            y = 20;
        }

        doc.setFontSize(14);
        doc.text(`${index + 1}. ${vuln.title}`, 20, y);
        y += 8;

        doc.setFontSize(11);
        doc.text(`Severity: ${vuln.severity}`, 25, y);
        y += 8;

        doc.text(`Description: ${vuln.description}`, 25, y);
        y += 8;

        doc.text("Attack Path:", 25, y);
        y += 8;

        if (vuln.attack_path && vuln.attack_path.length > 0) {
            vuln.attack_path.forEach(step => {
                doc.text(`- ${step}`, 30, y);
                y += 7;
            });
        } else {
            doc.text("- No attack path available", 30, y);
            y += 7;
        }

        if (vuln.recommendation) {
            doc.text("Recommendation:", 25, y);
            y += 8;
            doc.text(vuln.recommendation, 30, y);
            y += 10;
        }

        y += 8;
    });

    doc.save("vulniq_security_report.pdf");
}

function showResult(data) {
    document.getElementById("result").textContent = JSON.stringify(data, null, 2);
}

function setupDarkMode() {
    const modeToggle = document.getElementById("modeToggle");

    if (!modeToggle) return;

    modeToggle.addEventListener("click", function () {
        document.body.classList.toggle("dark");

        if (document.body.classList.contains("dark")) {
            modeToggle.innerHTML = "☀️ Light";
        } else {
            modeToggle.innerHTML = "🌙 Dark";
        }
    });
}
async function aiSearch() {
    const query = document.getElementById("searchQuery").value;

    if (!query) {
        alert("Please enter search text");
        return;
    }

    const response = await fetch(`${API_URL}/ai-search?query=${encodeURIComponent(query)}`);
    const data = await response.json();

    searchedIds = data.results.map(item => item.vulnerability.id);

    showResult(data);
    loadAll();
}
async function startScan() {

    const target =
        document.getElementById("scanTarget").value;

    if (!target) {
        alert("Enter target IP");
        return;
    }

    const response =
        await fetch(
            `${API_URL}/nmap-scan?target=${target}`
        );

    const data =
        await response.json();

    document.getElementById("result").textContent =
        data.scan_result || data.message;
}
async function loadCVEFeed() {
    const response = await fetch(`${API_URL}/cve-feed`);
    const data = await response.json();

    const container = document.getElementById("cveContainer");
    container.innerHTML = "";

    data.results.forEach(cve => {
        container.innerHTML += `
            <div class="cve-card">
                <div class="cve-header">
                    <h3>${cve.cve_id}</h3>
                    <span class="cve-badge ${cve.severity}">
                        ${cve.severity}
                    </span>
                </div>

                <h4>${cve.title}</h4>

                <p>${cve.description || "No description available"}</p>

                <div class="recommendation-section">
                    <h4>Recommendation</h4>
                    <p>${cve.recommendation || "Apply latest patches and monitor vendor advisories."}</p>
                </div>
            </div>
        `;
    });
}
async function loadAnalytics() {

    const response =
        await fetch(`${API_URL}/analytics`);

    const data =
        await response.json();

    document.getElementById(
        "analyticsBox"
    ).innerHTML = `

        <div class="vulnerability-card">

            <h3>Total Vulnerabilities:
                ${data.total_vulnerabilities}
            </h3>

            <h3>Nmap Scans:
                ${data.nmap_scans}
            </h3>

            <h3>Uploaded Reports:
                ${data.uploaded_reports}
            </h3>

        </div>

    `;
}