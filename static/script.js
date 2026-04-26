// ==========================
// FILTER TABLE
// ==========================
function filterTable(level) {
    const rows = document.querySelectorAll("#tableBody tr");

    rows.forEach(row => {
        if (level === "ALL") {
            row.style.display = "";
        } else {
            row.style.display =
                row.dataset.severity === level ? "" : "none";
        }
    });
}


// ==========================
// RUN SCAN (MAIN ACTION)
// ==========================
function runScan() {
    const loader = document.getElementById("loader");
    loader.style.display = "block";

    fetch("/run_scan", { method: "POST" })
        .then(res => res.json())
        .then(response => {
            const data = response.data;

            updateTable(data);
            updateMetrics(data);
            updateChart(data);
            updateDropdown(response.all_reports);
            updateLastScan();

            alert("Scan complete!");
        })
        .catch(err => {
            console.error("Scan failed:", err);
            alert("Scan failed. Check backend.");
        })
        .finally(() => {
            loader.style.display = "none";
        });
}


// ==========================
// UPDATE DROPDOWN
// ==========================
function updateDropdown(reports) {
    const dropdown = document.getElementById("reportDropdown");
    dropdown.innerHTML = "";

    reports.forEach(file => {
        const option = document.createElement("option");
        option.value = file;

        option.text = file
            .replace("report_", "")
            .replace(".json", "")
            .replace("_", " ");

        dropdown.appendChild(option);
    });

    // select latest automatically
    if (reports.length > 0) {
        dropdown.value = reports[0];
    }
}


// ==========================
// UPDATE TABLE
// ==========================
function updateTable(data) {
    const table = document.getElementById("tableBody");
    table.innerHTML = "";

    data.forEach(item => {
        const row = `
            <tr data-severity="${item.severity}">
                <td>${item.resource}</td>
                <td>${item.type}</td>
                <td>${item.issue}</td>
                <td>
                    <span class="badge ${item.severity.toLowerCase()}">
                        ${item.severity}
                    </span>
                </td>
            </tr>
        `;
        table.innerHTML += row;
    });
}


// ==========================
// UPDATE METRICS
// ==========================
function updateMetrics(data) {
    let critical = 0, high = 0, medium = 0;

    data.forEach(item => {
        if (item.severity === "CRITICAL") critical++;
        else if (item.severity === "HIGH") high++;
        else if (item.severity === "MEDIUM") medium++;
    });

    document.getElementById("criticalCount").innerText = critical;
    document.getElementById("highCount").innerText = high;
    document.getElementById("mediumCount").innerText = medium;
}


// ==========================
// UPDATE CHART
// ==========================
function updateChart(data) {
    let counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };

    data.forEach(item => {
        counts[item.severity]++;
    });

    chart.data.datasets[0].data = [
        counts.CRITICAL,
        counts.HIGH,
        counts.MEDIUM
    ];

    chart.update();
}


// ==========================
// LAST SCAN TIME
// ==========================
function updateLastScan() {
    fetch("/last_scan")
        .then(res => res.json())
        .then(data => {
            if (!data.last_scan) {
                document.getElementById("lastScan").innerText =
                    "Last scan: No scans yet";
                return;
            }

            const last = new Date(data.last_scan);
            const now = new Date();

            const diff = Math.floor((now - last) / 60000);

            document.getElementById("lastScan").innerText =
                diff <= 0
                    ? "Last scan: Just now"
                    : `Last scan: ${diff} min ago`;
        })
        .catch(() => {
            document.getElementById("lastScan").innerText =
                "Last scan: unavailable";
        });
}


// ==========================
// AUTO REFRESH LAST SCAN
// ==========================
setInterval(updateLastScan, 10000);
updateLastScan();