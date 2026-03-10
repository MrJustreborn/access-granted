from flask import Flask, render_template, request, redirect
import ipaddress
import datetime
import os
import subprocess

DYNAMIC_WHITELIST_FILE = "./whitelist_dynamic.conf"
DEFAULT_DURATION_HOURS = 24

app = Flask(__name__)

def write_whitelist(ip_or_subnet, duration_hours, comment=None):
    expire_time = datetime.datetime.now() + datetime.timedelta(hours=duration_hours)
    expire_str = expire_time.isoformat()
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
                    existing_ip = allow_line.replace("allow", "").replace(";", "").strip()
                    
                    parts = line[len("# expires at "):].split(" - ", 1)
                    existing_expires = parts[0].strip()
                    existing_comment = parts[1].strip() if len(parts) > 1 else ""

                    entries.append({
                        "ip": existing_ip,
                        "expires": existing_expires,
                        "comment": existing_comment
                    })
                i += 2
            else:
                i += 1

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

    print(entries)
    with open(DYNAMIC_WHITELIST_FILE, "w") as f:
        for entry in entries:
            comment_text = f" - {entry['comment']}" if entry["comment"] else ""
            f.write(f"# expires at {entry['expires']}{comment_text}\n")
            f.write(f"allow {entry['ip']};\n")

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
        if target == "client":
            write_whitelist(client_ip, duration, f"{duration}h")
        elif target == "subnet":
            write_whitelist(str(subnet), duration, f"{duration}h")
        return redirect("/")

    return render_template("index.html", client_ip=client_ip, subnet=subnet)

if __name__ == "__main__":
    app.run(host="::", port=5000)