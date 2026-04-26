function filterTable(level) {
    const rows = document.querySelectorAll("#table tr[data-severity]");

    rows.forEach(row => {
        if (level === "ALL") {
            row.style.display = "";
        } else {
            row.style.display =
                row.dataset.severity === level ? "" : "none";
        }
    });
}

function runScan() {
    fetch("/run-scan")
        .then(res => res.text())
        .then(msg => alert(msg));
}

function updateTable(data) {
    const table = document.getElementById("tableBody");
    table.innerHTML = "";

    data.forEach(item => {
        const row = `
            <tr>
                <td>${item.resource}</td>
                <td>${item.type}</td>
                <td>${item.issue}</td>
                <td>${item.severity}</td>
            </tr>
        `;
        table.innerHTML += row;
    });
}

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

function runScan() {
    fetch("/run_scan", { method: "POST" })
        .then(res => res.json())
        .then(response => {
            const data = response.data;

            updateTable(data);
            updateMetrics(data);
            updateChart(data);
            updateLastScan();

            alert("Scan complete!");
        });
}

function updateLastScan() {
    fetch("/last_scan")
        .then(res => res.json())
        .then(data => {
            const last = new Date(data.last_scan);
            const now = new Date();

            const diff = Math.floor((now - last) / 60000);

            document.getElementById("lastScan").innerText =
                `Last scan: ${diff} min ago`;
        });
}

setInterval(updateLastScan, 10000);
updateLastScan();