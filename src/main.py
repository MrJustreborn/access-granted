from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template, request, redirect, make_response
from urllib.parse import urlencode
import ipaddress
import datetime
import os
import subprocess

DYNAMIC_WHITELIST_FILE = "./data/whitelist_dynamic.conf"
DEFAULT_DURATION_HOURS = 24

app = Flask(__name__)

scheduler = BackgroundScheduler()
scheduler.start()

def cleanup_job():
    print("Running cleanup...")
    cleanup_expired()

scheduler.add_job(cleanup_job, 'interval', minutes=1)

def read_whitelist():
    """
    Reads the whitelist as:
    [{'ip': <str>, 'expires': <str ISO>, 'comment': <str>}]
    """
    entries = []

    if os.path.exists(DYNAMIC_WHITELIST_FILE):
        with open(DYNAMIC_WHITELIST_FILE, "r") as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("# expires at") and i + 1 < len(lines):
                allow_line = lines[i + 1].strip()
                if allow_line.startswith("allow"):
                    ip = allow_line.replace("allow", "").replace(";", "").strip()
                    parts = line[len("# expires at "):].split(" - ", 1)
                    expires = parts[0].strip()
                    comment = parts[1].strip() if len(parts) > 1 else ""
                    entries.append({
                        "ip": ip,
                        "expires": expires,
                        "comment": comment
                    })
                i += 2
            else:
                i += 1
    return entries

def write_whitelist_file(entries):
    """
    Writes the whitelist as:
    entries = [{'ip':..., 'expires':..., 'comment':...}, ...]
    """
    tmp_file = DYNAMIC_WHITELIST_FILE + ".tmp"
    with open(tmp_file, "w") as f:
        for entry in entries:
            comment_text = f" - {entry['comment']}" if entry["comment"] else ""
            f.write(f"# expires at {entry['expires']}{comment_text}\n")
            f.write(f"allow {entry['ip']};\n")
    os.replace(tmp_file, DYNAMIC_WHITELIST_FILE)

def cleanup_expired():
    """
    Removes expired ips from whitelist
    """
    now = datetime.datetime.now()
    entries = read_whitelist()

    new_entries = []
    for entry in entries:
        try:
            expire_time = datetime.datetime.fromisoformat(entry["expires"])
            if expire_time > now:
                new_entries.append(entry)
        except ValueError:
            pass

    if len(new_entries) != len(entries):
        write_whitelist_file(new_entries)

def write_whitelist(ip_or_subnet, duration_hours, comment=None):
    expire_time = datetime.datetime.now() + datetime.timedelta(hours=duration_hours)
    expire_str = expire_time.isoformat()
    entries = read_whitelist()

    found = False
    for entry in entries:
        if entry["ip"] == ip_or_subnet:
            entry["expires"] = expire_str
            if comment is not None:
                entry["comment"] = comment
            found = True
            break

    if not found:
        entries.append({
            "ip": ip_or_subnet,
            "expires": expire_str,
            "comment": comment or ""
        })

    write_whitelist_file(entries)

@app.route("/", methods=["GET", "POST"])
def index():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    client_ip = client_ip.split(",")[0].strip()

    try:
        ip_obj = ipaddress.ip_address(client_ip)

        if isinstance(ip_obj, ipaddress.IPv6Address):
            subnet = ipaddress.IPv6Network(f"{client_ip}/64", strict=False)
        else:
            subnet = ipaddress.IPv4Network(f"{client_ip}/24", strict=False)

    except ValueError:
        client_ip = "invalid"
        subnet = "invalid"

    if request.method == "POST":
        target = request.form.get("target")
        duration = int(request.form.get("duration", DEFAULT_DURATION_HOURS))
        comment = request.form.get("comment")
        if target == "client":
            write_whitelist(client_ip, duration, comment)
        elif target == "subnet":
            write_whitelist(str(subnet), duration, comment)
        params = urlencode({
            "ip": client_ip,
            "subnet": str(subnet),
            "duration": duration,
            "comment": comment or ""
        })
        return redirect(f"/granted?{params}")

    return render_template("index.html", client_ip=client_ip, subnet=subnet)

@app.route("/granted", methods=["GET", "POST"])
def granted():
    if request.method == "POST":
        target = request.form.get("target")
        if target == "back":
            return redirect("/")
        elif target == "next":
            return redirect("http://google.com")
    
    client_ip = request.args.get("ip")
    subnet = request.args.get("subnet")
    duration = request.args.get("duration")
    comment = request.args.get("comment")
    return render_template(
            "access-granted.html",
            client_ip=client_ip,
            subnet=subnet,
            duration=duration,
            comment=comment
        )

@app.route("/cleanup", methods=["POST"])
def cleanup():
    cleanup_expired()
    response = make_response('', 204)
    return response

if __name__ == "__main__":
    app.run(host="::", port=5000)