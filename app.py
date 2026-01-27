from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)


def run_nmap(target):
    """
    Lance un scan Nmap simple sur la cible
    """
    command = ["nmap", "-sV", target]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout


@app.route("/", methods=["GET", "POST"])
def index():
    target = None
    selected_scans = []
    scan_results = {}

    if request.method == "POST":
        target = request.form.get("target")

        if request.form.get("scan_nmap"):
            selected_scans.append("Nmap")
            output = run_nmap(target)
            scan_results["Nmap"] = output

        if request.form.get("scan_nikto"):
            selected_scans.append("Nikto")
            scan_results["Nikto"] = "Scan Nikto non implémenté pour le moment."

        if request.form.get("scan_sqlmap"):
            selected_scans.append("SQLMap")
            scan_results["SQLMap"] = "Scan SQLMap non implémenté pour le moment."

    return render_template(
        "main_page.html",
        target=target,
        scans=selected_scans,
        results=scan_results
    )


if __name__ == "__main__":
    app.run(debug=True)
