# Silent installation

`install_HomeLAB-dns.sh` supports a fully unattended installation. Command-line values override values loaded from JSON.

## Full CLI example

```bash
sudo ./install_HomeLAB-dns.sh --silent \
  --web-ui-ip 10.0.0.53 \
  --port 81 \
  --forward-dns-server 1.1.1.1 \
  --panel-login admin \
  --panel-password 'CHANGE_ME_STRONG_PASSWORD' \
  --panel-api-token 'cldns_CHANGE_ME_WITH_A_LONG_RANDOM_TOKEN_VALUE'
```

Supported provisioning flags:

- `--web-ui-ip IP`
- `--port PORT` or `--web-ui-port PORT`
- `--forward-dns-server IP`
- `--panel-login LOGIN`
- `--panel-password PASSWORD`
- `--panel-password-file FILE`
- `--panel-api-token TOKEN`
- `--panel-api-token-file FILE`
- `--config FILE` / `--json FILE`
- `--silent` / `--non-interactive`
- `--result-json FILE`

## Safer secret handling

For automation, prefer secret files instead of putting secrets in the process arguments or shell history:

```bash
sudo install -m 0600 /dev/null /root/dns-panel-password
sudo install -m 0600 /dev/null /root/dns-api-token
printf '%s\n' 'CHANGE_ME_STRONG_PASSWORD' | sudo tee /root/dns-panel-password >/dev/null
printf '%s\n' 'cldns_CHANGE_ME_WITH_A_LONG_RANDOM_TOKEN_VALUE' | sudo tee /root/dns-api-token >/dev/null

sudo ./install_HomeLAB-dns.sh --silent \
  --web-ui-ip 10.0.0.53 \
  --port 81 \
  --forward-dns-server 1.1.1.1 \
  --panel-login admin \
  --panel-password-file /root/dns-panel-password \
  --panel-api-token-file /root/dns-api-token
```

Secret files must be absolute paths, regular non-symlink files, and mode `0600` or stricter.

## JSON example

```json
{
  "forward_dns_server": "1.1.1.1",
  "web_ui_ip": "10.0.0.53",
  "panel_login": "admin",
  "panel_password": "CHANGE_ME_STRONG_PASSWORD",
  "panel_api_token": "cldns_CHANGE_ME_WITH_A_LONG_RANDOM_TOKEN_VALUE",
  "port": 81
}
```

The default provisioning file is `/root/configs/install_HomeLAB-dns.json`. It must be root-owned and mode `0600` or stricter.

## Mixed JSON + CLI

JSON can contain only part of the provisioning data. CLI values override matching JSON values:

```bash
sudo ./install_HomeLAB-dns.sh \
  --config /root/configs/install_HomeLAB-dns.json \
  --silent \
  --web-ui-ip 10.0.0.54 \
  --port 8081
```

With `--silent`, normal successful output is suppressed. Errors are still written to stderr. `--result-json /absolute/path/result.json` can be used when automation needs the resulting panel URL and installation metadata.
