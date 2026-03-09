Reload nginx after the ip-whitelist config has been changed

* cp ./* /etc/systemd/system/

* sudo systemctl daemon-reload

* sudo systemctl enable --now nginx-config-reload.path