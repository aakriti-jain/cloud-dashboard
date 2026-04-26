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

function runScan() {
    fetch("/run_scan", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            alert("Scan complete!");
            location.reload();
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