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