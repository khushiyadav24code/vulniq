const API_URL = "http://127.0.0.1:8000";

let riskChart = null;

window.onload = function () {
    if (localStorage.getItem("loggedIn") === "true") {
        document.getElementById("loginPage").style.display = "none";
        document.getElementById("dashboard").style.display = "block";

        getStats();
        loadAll();
    } else {
        document.getElementById("loginPage").style.display = "flex";
        document.getElementById("dashboard").style.display = "none";
    }
};
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
        title: title,
        description: description,
        severity: severity
    };

    const response = await fetch(`${API_URL}/add`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
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

    showResult(data);
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

    drawChart(data.high, data.medium, data.low);
}

function drawChart(high, medium, low) {
    const ctx = document.getElementById("riskChart");

    if (!ctx) return;

    if (riskChart) {
        riskChart.destroy();
    }

    riskChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["High", "Medium", "Low"],
            datasets: [{
                data: [high, medium, low],
                backgroundColor: ["#ef4444", "#f59e0b", "#22c55e"],
                borderWidth: 2
            }]
        },
        options: {
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
        div.className = "vuln-item";

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
                    ?
                    `
                    <ol>
                        ${vuln.attack_path
                            .map(step => `<li>${step}</li>`)
                            .join("")}
                    </ol>
                    `
                    :
                    `<p class="empty">No attack path available</p>`
                }
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

function showResult(data) {
    document.getElementById("result").textContent = JSON.stringify(data, null, 2);
}
async function downloadReport() {
    const response = await fetch(`${API_URL}/all`);
    const data = await response.json();

    const fileData = JSON.stringify(data, null, 2);

    const blob = new Blob([fileData], {
        type: "application/json"
    });

    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "vulniq_report.json";
    a.click();

    URL.revokeObjectURL(url);
}
const modeToggle = document.getElementById("modeToggle");

if (modeToggle) {

    modeToggle.addEventListener("click", function () {

        document.body.classList.toggle("dark");

        if (document.body.classList.contains("dark")) {

            modeToggle.innerHTML = "☀️ Light";

        } else {

            modeToggle.innerHTML = "🌙 Dark";
        }
    });

}
function login() {
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    if (email === "admin@vulniq.com" && password === "admin123") {
        document.getElementById("loginPage").style.display = "none";
        document.getElementById("dashboard").style.display = "block";

        getStats();
        loadAll();
    } else {
        alert("Invalid email or password");
    }
}
async function registerUser() {
    const name = document.getElementById("regName").value;
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    if (!name || !email || !password) {
        document.getElementById("loginMessage").innerText = "Please fill all fields";
        return;
    }

    const response = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: name,
            email: email,
            password: password
        })
    });

    const data = await response.json();
    document.getElementById("loginMessage").innerText = data.message;
}

async function loginUser() {
    const name = document.getElementById("regName").value || "User";
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    if (!email || !password) {
        document.getElementById("loginMessage").innerText = "Please enter email and password";
        return;
    }

    const response = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: name,
            email: email,
            password: password
        })
    });

    const data = await response.json();
if (data.success) {
    localStorage.setItem("loggedIn", "true");
    localStorage.setItem("userEmail", email);

    document.getElementById("loginPage").style.display = "none";
    document.getElementById("dashboard").style.display = "block";

    getStats();
    loadAll();

    }else {
        document.getElementById("loginMessage").innerText = data.message;
    }
}
function logoutUser() {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("userEmail");

    document.getElementById("dashboard").style.display = "none";
    document.getElementById("loginPage").style.display = "flex";

    document.getElementById("loginEmail").value = "";
    document.getElementById("loginPassword").value = "";
    document.getElementById("regName").value = "";

    document.getElementById("loginMessage").innerText =
        "Logged out successfully";
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

        y += 8;
    });

    doc.save("vulniq_security_report.pdf");
}