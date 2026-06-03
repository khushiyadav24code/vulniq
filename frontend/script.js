const API_URL = "http://127.0.0.1:8000";

let riskChart = null;

window.onload = function () {
    getStats();
    loadAll();
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