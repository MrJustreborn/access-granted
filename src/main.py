from flask import Flask, render_template, request, redirect
import ipaddress
import datetime
import os
import subprocess

DYNAMIC_WHITELIST_FILE = "./whitelist_dynamic.conf"
DEFAULT_DURATION_HOURS = 24

app = Flask(__name__)

def write_whitelist(ip_or_subnet, duration_hours):
    expire_time = datetime.datetime.now() + datetime.timedelta(hours=duration_hours)
    with open(DYNAMIC_WHITELIST_FILE, "w") as f:
        f.write(f"# expires at {expire_time.isoformat()}\n")
        f.write(f"allow {ip_or_subnet};\n")

@app.route("/", methods=["GET", "POST"])
def index():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        ip_obj = ipaddress.IPv6Address(client_ip)
        subnet = ipaddress.IPv6Network(f"{client_ip}/64", strict=False)
    except ipaddress.AddressValueError:
        client_ip = "invalid"
        subnet = "invalid"

    if request.method == "POST":
        target = request.form.get("target")
        duration = int(request.form.get("duration", DEFAULT_DURATION_HOURS))
        if target == "client":
            write_whitelist(client_ip, duration)
        elif target == "subnet":
            write_whitelist(str(subnet), duration)
        return redirect("/")

    return render_template("index.html", client_ip=client_ip, subnet=subnet)

if __name__ == "__main__":
    app.run(host="::", port=5000)