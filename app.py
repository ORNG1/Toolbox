from flask import Flask, render_template, request, redirect, url_for, session, flash
import subprocess
import os
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Secret key for session. In production, set SECRET_KEY env var.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# When False, commands will not actually be executed — they are shown as dry-runs.
RUN_COMMANDS = False

# Simple user store (no DB). For multi-user or persistent storage, use a DB.
# Default admin password can be set with env var TOOLBOX_ADMIN_PW (default: 'admin').
USERS = {
    "admin": generate_password_hash(os.environ.get("TOOLBOX_ADMIN_PW", "admin"))
}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def run_subprocess(command):
    if not RUN_COMMANDS:
        return "Dry-run: " + " ".join(command)

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout or result.stderr


def run_nmap(target, quick=False, service_os=False, full_tcp=False, nse=False):
    cmd = ["nmap"]
    if quick:
        cmd.append("-F")
    if service_os:
        cmd.extend(["-sV", "-O"])
    if full_tcp:
        cmd.extend(["-p-", "-sV"])
    if nse:
        cmd.extend(["--script", "default"])
    cmd.append(target)
    return run_subprocess(cmd)


def run_nikto(target, standard=False, ssl=False, dirs=False, tuning=False):
    cmd = ["nikto", "-h", target]
    if ssl:
        cmd.append("-ssl")
    if dirs:
        cmd.append("-Tuning 9")
    if tuning:
        cmd.append("-Tuning 4")
    return run_subprocess(cmd)


def run_sqlmap(target, test=False, enum_dbs=False, extract_tables=False, dump=False):
    cmd = ["sqlmap", "-u", target, "--batch"]
    if test:
        cmd.append("--risk=1")
    if enum_dbs:
        cmd.append("--dbs")
    if extract_tables:
        cmd.append("--tables")
    if dump:
        cmd.append("--dump")
    return run_subprocess(cmd)


def run_hydra(target, ssh=False, ftp=False, http_form=False, enum_users=False):
    commands = []
    if ssh:
        commands.append(["hydra", "-L", "users.txt", "-P", "passlist.txt", target, "ssh"])
    if ftp:
        commands.append(["hydra", "-L", "users.txt", "-P", "passlist.txt", target, "ftp"])
    if http_form:
        commands.append(["hydra", "-L", "users.txt", "-P", "passlist.txt", target, "http-form-post", "/login.php:username=^USER^&password=^PASS^:F=invalid"])
    if enum_users:
        commands.append(["hydra", "-L", "common_users.txt", "-e", "ns", target, "ssh"])

    outputs = []
    for c in commands:
        outputs.append(run_subprocess(c))
    return "\n".join(outputs) if outputs else "No hydra actions selected."


def run_john(single=False, dictionary=False, incremental=False, audit=False):
    cmds = []
    if single:
        cmds.append(["john", "--single", "hashes.txt"])
    if dictionary:
        cmds.append(["john", "--wordlist=rockyou.txt", "hashes.txt"])
    if incremental:
        cmds.append(["john", "--incremental", "hashes.txt"])
    if audit:
        cmds.append(["john", "--show", "hashes.txt"])

    outputs = []
    for c in cmds:
        outputs.append(run_subprocess(c))
    return "\n".join(outputs) if outputs else "No John actions selected."


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    target = None
    selected_scans = []
    scan_results = {}

    if request.method == "POST":
        target = request.form.get("target")

        # Nmap options
        nmap_quick = bool(request.form.get("nmap_quick"))
        nmap_service_os = bool(request.form.get("nmap_service_os"))
        nmap_full_tcp = bool(request.form.get("nmap_full_tcp"))
        nmap_nse = bool(request.form.get("nmap_nse"))

        if any([nmap_quick, nmap_service_os, nmap_full_tcp, nmap_nse]):
            selected_scans.append("Nmap")
            scan_results["Nmap"] = run_nmap(
                target,
                quick=nmap_quick,
                service_os=nmap_service_os,
                full_tcp=nmap_full_tcp,
                nse=nmap_nse,
            )

        # Nikto options
        nikto_standard = bool(request.form.get("nikto_standard"))
        nikto_ssl = bool(request.form.get("nikto_ssl"))
        nikto_dirs = bool(request.form.get("nikto_dirs"))
        nikto_tuning = bool(request.form.get("nikto_tuning"))

        if any([nikto_standard, nikto_ssl, nikto_dirs, nikto_tuning]):
            selected_scans.append("Nikto")
            scan_results["Nikto"] = run_nikto(
                target,
                standard=nikto_standard,
                ssl=nikto_ssl,
                dirs=nikto_dirs,
                tuning=nikto_tuning,
            )

        # SQLMap options
        sqlmap_test = bool(request.form.get("sqlmap_test"))
        sqlmap_enum_dbs = bool(request.form.get("sqlmap_enum_dbs"))
        sqlmap_extract_tables = bool(request.form.get("sqlmap_extract_tables"))
        sqlmap_dump = bool(request.form.get("sqlmap_dump"))

        if any([sqlmap_test, sqlmap_enum_dbs, sqlmap_extract_tables, sqlmap_dump]):
            selected_scans.append("SQLMap")
            scan_results["SQLMap"] = run_sqlmap(
                target,
                test=sqlmap_test,
                enum_dbs=sqlmap_enum_dbs,
                extract_tables=sqlmap_extract_tables,
                dump=sqlmap_dump,
            )

        # Hydra options
        hydra_ssh = bool(request.form.get("hydra_ssh"))
        hydra_ftp = bool(request.form.get("hydra_ftp"))
        hydra_http_form = bool(request.form.get("hydra_http_form"))
        hydra_enum_users = bool(request.form.get("hydra_enum_users"))

        if any([hydra_ssh, hydra_ftp, hydra_http_form, hydra_enum_users]):
            selected_scans.append("Hydra")
            scan_results["Hydra"] = run_hydra(
                target,
                ssh=hydra_ssh,
                ftp=hydra_ftp,
                http_form=hydra_http_form,
                enum_users=hydra_enum_users,
            )

        # John the Ripper options
        john_single = bool(request.form.get("john_single"))
        john_dictionary = bool(request.form.get("john_dictionary"))
        john_incremental = bool(request.form.get("john_incremental"))
        john_audit = bool(request.form.get("john_audit"))

        if any([john_single, john_dictionary, john_incremental, john_audit]):
            selected_scans.append("John the Ripper")
            scan_results["John the Ripper"] = run_john(
                single=john_single,
                dictionary=john_dictionary,
                incremental=john_incremental,
                audit=john_audit,
            )

    return render_template(
        "main_page.html",
        target=target,
        scans=selected_scans,
        results=scan_results,
    )


@app.route("/nmap")
@login_required
def nmap_page():
    return render_template("nmap.html")


@app.route("/nikto")
@login_required
def nikto_page():
    return render_template("nikto.html")


@app.route("/sqlmap")
@login_required
def sqlmap_page():
    return render_template("sqlmap.html")


@app.route("/hydra")
@login_required
def hydra_page():
    return render_template("hydra.html")


@app.route("/john")
@login_required
def john_page():
    return render_template("john.html")


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_hash = USERS.get(username)
        if user_hash and check_password_hash(user_hash, password):
            session['logged_in'] = True
            session['username'] = username
            next_page = request.args.get('next') or url_for('index')
            return redirect(next_page)
        flash('Identifiants invalides', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


if __name__ == "__main__":
    app.run(debug=True)
