# CrowdStrike Public Endpoint / IP Comparison Note

Date checked: 2026-07-28

## Purpose

This note keeps known/observed CrowdStrike-related public endpoints for quick comparison against Windows outbound HTTP/HTTPS logs from `devfm11-per` (`192.168.254.95`).

## Important caveat

CrowdStrike Falcon cloud endpoints are normally documented and allowed by FQDN/cloud region, not as a small stable public IP allowlist. The IPs can sit behind AWS/ELB/EC2 and may change.

Use this note as investigation evidence only:

- A matching TLS certificate from CrowdStrike is strong evidence that the destination currently serves a CrowdStrike endpoint.
- AWS CIDR membership alone is not enough to prove CrowdStrike.
- `System` / PID 4 in Windows WFP logs means the original user-mode process may not be exposed; it does not by itself prove which agent/driver initiated the connection.

## Observed suspicious PID 4 destinations from outbound logs

These were seen as `System` / PID 4 from `192.168.254.95`.

| IP | Port | AWS public range match | Reverse DNS | TLS certificate observed | Assessment |
|---|---:|---|---|---|---|
| `52.35.162.27` | 443 | `52.32.0.0/14`, `us-west-2`, `AMAZON`/`EC2` | `ec2-52-35-162-27.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint |
| `35.162.224.228` | 443 | `35.160.0.0/13`, `us-west-2`, `AMAZON`/`EC2` | `ec2-35-162-224-228.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint |
| `35.80.210.147` | 443 | `35.80.0.0/12`, `us-west-2`, `AMAZON`/`EC2` | `ec2-35-80-210-147.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint |
| `35.160.213.193` | 443 | `35.160.0.0/13`, `us-west-2`, `AMAZON`/`EC2` | `ec2-35-160-213-193.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint |
| `34.209.165.130` | 443 | `34.208.0.0/12`, `us-west-2`, `AMAZON`/`EC2` | `ec2-34-209-165-130.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint |
| `35.162.239.174` | 443 | `35.160.0.0/13`, `us-west-2`, `AMAZON`/`EC2` | `ec2-35-162-239-174.us-west-2.compute.amazonaws.com` | `O=CrowdStrike, Inc., CN=ts01-gyr-maverick.cloudsink.net` | Very likely CrowdStrike cloud endpoint; previously observed |
| `169.254.169.254` | 80 | Not an AWS public CIDR; link-local metadata service address | none | N/A | Still anomalous on non-cloud Windows server; not a CrowdStrike public IP |

## Commands used for verification

```bash
# AWS public CIDR comparison
python3 - <<'PY'
import urllib.request, json, ipaddress
ips=['52.35.162.27','35.162.224.228','35.80.210.147','34.209.165.130','35.162.239.174','35.160.213.193','169.254.169.254']
data=json.load(urllib.request.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json', timeout=20))
for ip in ips:
    addr=ipaddress.ip_address(ip)
    print('\n', ip)
    for p in data['prefixes']:
        if addr in ipaddress.ip_network(p['ip_prefix']):
            print(p)
PY

# Reverse DNS
for ip in 52.35.162.27 35.162.224.228 35.80.210.147 35.160.213.193 34.209.165.130 35.162.239.174; do
  getent hosts "$ip"
done

# TLS certificate check
for ip in 52.35.162.27 35.162.224.228 35.80.210.147 35.160.213.193 34.209.165.130 35.162.239.174; do
  timeout 6 openssl s_client -connect "$ip:443" -brief </dev/null 2>&1 \
    | egrep -i 'Peer certificate|Verification|Protocol|Ciphersuite|CN|subject|issuer'
done
```

## Current conclusion

The PID 4 AWS destinations above are most likely CrowdStrike Falcon cloud traffic based on live TLS certificate evidence (`CrowdStrike, Inc.` / `ts01-gyr-maverick.cloudsink.net`).

However, process attribution from WFP still shows only `System` / PID 4, so phrase reports carefully:

> Based on destination IP, AWS range, reverse DNS, and TLS certificate checks, these AWS connections appear CrowdStrike-related. The Windows WFP log records them under `System` / PID 4, so the initiating kernel driver/agent is not directly exposed in this log.
