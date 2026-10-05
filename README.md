# Modern-IoT-Scanner
A cool and modern IoT scanner :D happy skidding :D :D :D :D, jokes aside below is the real readme, unless ????


## Features:

- **173 device signatures** covering IP cameras, NVRs, printers, NAS, routers, switches, access points, VoIP phones, UPS/PDU, IPMI/BMC, HVAC/BMS, access control, and more
- **Async parallel scanning** via AnyEvent 10+ concurrent connections by default (configurable)
- **Multi port scanning** 60 IoT ports per device, or specify your own subset
- **Auto HTTPS detection** for ports 443, 8443, 4443, 10443, 9443, 1443, 4343
- **Three auth methods** HTTP Basic, form based POST login, and unauthenticated (expect200) detection
- **Device fingerprinting** via HTTP response body (title tags, content patterns), Server header, and WWW-Authenticate header
- **Multiple output formats** plain text, CSV, JSON
- **HTTP redirect following** with loop protection (max 5 hops)
- **META refresh URL detection** for devices that redirect via HTML
- **Configurable timeouts** and concurrency
- **Extensible JSON config** add your own devices without touching the scanner code

## Requirements

**Perl 5.10+** with the following modules:

```
AnyEvent::HTTP
MIME::Base64
Digest::SHA
JSON
Data::Dumper
```

### Install dependencies

```bash
# Debian/Ubuntu
sudo apt install libanyevent-perl libanyevent-http-perl libjson-perl

# RHEL/CentOS/Fedora
sudo yum install perl-AnyEvent-HTTP perl-JSON

# Via CPAN (any platform)
cpan AnyEvent::HTTP JSON
```

## Quick Start

```bash
# Scan a single IP
perl iotScanner.pl 192.168.1.100

# Scan a range
perl iotScanner.pl 192.168.1.1-192.168.1.254

# Scan multiple ranges and individual IPs
perl iotScanner.pl 10.0.1.1-10.0.1.254,10.0.2.1-10.0.2.254,172.16.0.5

# Quick scan
perl iotScanner.pl 10.0.0.0-10.0.0.254 ports=80,443,8080,8443

# Full scan with JSON output, 20 parallel connections, 15s timeout
perl iotScanner.pl 10.0.0.0-10.0.0.254 output=json concurrency=20 timeout=15

# CSV output for spreadsheet import
perl iotScanner.pl 10.0.0.0-10.0.0.254 output=csv > results.csv

# Debug mode
perl iotScanner.pl 192.168.1.1 debug
```

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| cfgFile=<path> | devices.cfg | Path to the device config JSON file |
| devCfgUrl=<url> | - | Load device config from a remote URL instead of a file |
| ports=<p1,p2,...> | From config | Override the port list (comma separated) |
| concurrency=<n> | 10 | Number of parallel HTTP connections |
| timeout=<sec> | 10 | HTTP timeout per request in seconds |
| output=<format> | text | Output format: text, json, or csv |
| debug[=level] | off | Enable debug output (level 1-3) |

## Output

### Text (default)
```
device 192.168.1.50 is of type Hikvision still has default password
device 192.168.1.51 of type Hikvision has changed password
device 192.168.1.100 is of type HP Printer still has default password
device 192.168.1.200: failed to establish TCP connection
```

### JSON
```json
{"ip":"192.168.1.50","port":80,"devType":"Hikvision","result":"default_password"}
{"ip":"192.168.1.51","port":80,"devType":"Hikvision","result":"password_changed"}
{"ip":"192.168.1.100","port":631,"devType":"HP Printer","result":"default_password"}
```

### CSV
```
ip,port,devType,result
192.168.1.50,80,Hikvision,default_password
192.168.1.51,80,Hikvision,password_changed
192.168.1.100,631,HP Printer,default_password
```

## Config File Format

The config file (devices.cfg) is a JSON object where each key is a device type name and the value defines how to detect and authenticate against that device.

### Entry structure

```json
{
  "Hikvision": {
    "comment": "Older firmware uses 12345. Newer requires first-login set. Check CVE-2021-36260.",
    "devTypePattern": [
      ["body", ""],
      ["regex", "(?i)hikvision"]
    ],
    "nextUrl": ["string", "/ISAPI/Security/userCheck"],
    "auth": ["basic", "admin:12345"],
    "ports": [80, 443, 8000, 8443]
  }
}
```

### Fields:

#### devTypePattern - How to identify the device

A two element array: [source, matcher].

**Source** (where to look):
| Source | Description |
|---|---|
| `["body", ""]` | Search the full HTTP response body |
| `["body", "title"]` | Extract content from `<title>` tags |
| `["header", "server"]` | Check the `Server` response header |
| `["header", "www-authenticate"]` | Check the `WWW-Authenticate` header |

**Matcher** (how to match):
| Matcher | Description |
|---|---|
| `["regex", "pattern1", "pattern2"]` | All regex patterns must match (AND logic) |
| `["==", "exact string"]` | Exact string match |
| `["substr", "substring"]` | Substring match |

#### nextUrl / loginUrlPattern - Where to send the login attempt

Use one of:

- `"nextUrl": ["string", "/login/path"]` - Static URL path to test authentication against
- `"loginUrlPattern": "regex(capture)"` - Extract the login URL from the response body using a regex with a capture group

#### `auth` - Authentication method

**HTTP Basic Auth:**
```json
"auth": ["basic", "admin:password"]
```
Sends `Authorization: Basic <base64>` header. A `200` response = default creds still work. A `401` = password was changed.

**HTTP Basic Auth (no password):**
```json
"auth": ["basic", ""]
```
Sends a plain GET with no auth header. A `200` = device has no password set.

**Form-based POST:**
```json
"auth": ["form", "", "username=admin&password=admin", "body", "regex", "success_pattern"]
```
Format: `["form", subtype, postdata, check_location, check_method, check_value]`

- `subtype`: `""` for direct POST, `"sub..."` to substitute extracted form data
- `postdata`: URL-encoded POST body (use `$1`, `$2` for extracted values)
- `check_location`: `"body"` to check the response body
- `check_method`: `"regex"` or `"!substr"`
- `check_value`: Pattern to match for success

**No Authentication (expect200):**
```json
"auth": ["expect200", ""]
```
Device has no login at all - a `200` on the URL means it's wide open.

#### `extractFormData` - Extract values from the page before login

```json
"extractFormData": ["name=\"_csrf\"\\s+value=\"(.*?)\""]
```
Array of regexes with capture groups. Extracted values are substituted into the POST data as `$1`, `$2`, etc.

#### `ports` - Known ports for this device type

```json
"ports": [80, 443, 8080, 8443]
```
The scanner builds a union of all ports across all device configs, then tests every IP on every port.

#### `comment` - Notes

```json
"comment": "Default creds. Known CVE. Additional context."
```
Not used by the scanner documentation only.

## Supported Devices (173)

### IP Cameras (30+)
ACTi, Amcrest, American Dynamics, Arecont, Bosch Security, Brickcom, D-Link DCS, FLIR, Foscam, GeoVision, Hanwha Wisenet, Hikvision, Honeywell Camera, IQinVision, JVC, Lorex, Milesight, Panasonic Camera, Pelco, Q-See, Reolink, SAMSUNG TECHWIN NVR, Sentry360, Speco, Stardot, Swann, Trendnet, Uniview, Vivotek, W-Box, Zmodo, axis, basler, mobotix

### DVR / NVR
Dahua, Dahua NVR, Hikvision NVR

### Network Printers & MFPs
Brother Printer, Canon Printer, Epson Printer, HP Printer, Konica Minolta, Kyocera Printer, Lexmark Printer, OKI Printer, Ricoh Printer, Samsung Printer, Sharp Printer, Toshiba eStudio, Xerox Printer

### Label / Receipt Printers
Honeywell Intermec Printer, Star Micronics Receipt, Zebra Printer

### NAS / Storage
Asustor NAS, Buffalo NAS, Netgear ReadyNAS, QNAP, Synology DSM, TerraMaster NAS, Western Digital MyCloud

### Routers / Firewalls / Switches / Access Points
ASUS Router, Aruba IAP, Cambium AP, Cisco SMB, DrayTek Vigor, EnGenius AP, Fortinet FortiGate, HPE Aruba Switch, Linksys, MikroTik, Netgear Router, OPNsense, Palo Alto, Peplink, Ruckus AP, Sierra Wireless, SonicWall, TP-Link Router, Teltonika, Ubiquiti EdgeOS, Zyxel, pfSense

### VoIP Phones & PBX
Avaya Phone, Cisco SPA Phone, Fanvil Phone, FreePBX, Grandstream, Grandstream UCM, Mitel Phone, Polycom VVX, Snom Phone, Yealink Phone, Yeastar PBX

### Conference & AV Equipment
AMX Harman, Barco ClickShare, Crestron, DTEN, Extron

### Projectors
BenQ Projector, Christie Projector, Epson Projector, NEC Projector, Panasonic Projector

### UPS / PDU
APC UPS, CyberPower UPS, Eaton UPS, Raritan PDU, Server Technology PDU, Tripp Lite UPS

### Server IPMI / BMC
Cisco CIMC, Dell iDRAC, HPE iLO, Lenovo XClarity, Supermicro IPMI

### KVM / Console Servers
ATEN KVM, Avocent KVM, Digi Console, Lantronix Console, Opengear Console, Raritan KVM

### HVAC / Building Management
Carrier i-Vu, Honeywell Niagara, Johnson Controls Metasys, Schneider EcoStruxure, Siemens Desigo

### Access Control
Gallagher Access, Honeywell NetAXS, ZKTeco Access

### Environmental Monitoring
AKCP SensorProbe, Room Alert AVTECH

### Digital Signage
BrightSign, Scala Signage

### Smart Home / IoT Hubs
GoGoGate, Home Assistant, Hubitat, Philips Hue Bridge, Shelly, Tasmota, Wemo Belkin

### Network Audio / Media
Bose SoundTouch, Denon Marantz AVR, Sonos, Yamaha MusicCast

### Energy / Solar / EV
Enphase Envoy, SMA Inverter, SolarEdge Inverter, Wallbox EV Charger

### 3D Printers
Creality K1, OctoPrint, PrusaLink

### Industrial / SCADA
ABB PLC, Beckhoff TwinCAT, HMS Anybus, Moxa Serial Gateway, PAX Payment Terminal, Phoenix Contact PLC, Wago PLC

### Time Clocks
Anviz Time Clock, Kronos InTouch

### Monitoring
PRTG Probe

### Miscellaneous
Raspberry Pi, OpenSprinkler, RainMachine, TP-Link VIGI

## Ports Scanned

When using the full config, the scanner tests for 60 unique ports:

```
80, 81, 85, 88, 443, 502, 623, 631, 1024, 1319, 1400, 1443, 2455,
3002, 3011, 3052, 3629, 4000, 4001, 4343, 4352, 4370, 4408, 4443,
4911, 5000, 5001, 5010, 7125, 7142, 8000, 8001, 8080, 8088, 8089,
8090, 8123, 8181, 8291, 8443, 8728, 8729, 8904, 9000, 9090, 9100,
9443, 10443, 17988, 18080, 22222, 30718, 37777, 39501, 41794, 47808,
48898, 49153, 49154, 49155
```

For faster scanning, use the quick pass port set:
```bash
perl iotScanner.pl <range> ports=80,443,8080,8443
```

## Performance Notes

- Full scan: 60 ports x 254 hosts = 15,240 connection attempts per /24 subnet
- Quick scan (4 ports): 4 x 254 = 1,016 connections finishes in seconds
- Default concurrency of 10 is conservative. For large networks, concurrency=50 is reasonable on a decent machine
- Each connection has a configurable timeout (default 10s). Unreachable hosts timeout once per port

## Adding Your Own Devices

Create a new entry in the config file:

```json
"My Custom Device": {
    "comment": "Notes about this device, known CVEs, etc.",
    "devTypePattern": [
        ["body", "title"],
        ["substr", "My Device Web UI"]
    ],
    "nextUrl": ["string", "/api/login"],
    "auth": ["basic", "admin:admin"],
    "ports": [80, 443]
}
```

1. Browse to the device's web interface
2. View the page source and HTTP response headers
3. Find a unique string in the title, body, or server header
4. Build the `devTypePattern` to match it
5. Identify the login endpoint and auth method
6. Test the default credentials listed in the device's documentation

## Known CVEs Referenced

The config includes notes about known vulnerabilities for many devices:

- **CVE-2021-36260** Hikvision command injection
- **CVE-2023-28771**  Zyxel unauthenticated command injection
- **CVE-2022-24990** TerraMaster unauthenticated RCE
- **CVE-2023-22611**  APC UPS authentication bypass
- **CVE-2023-6926**  Crestron authentication bypass
- **CVE-2018-15473** MikroTik Winbox exploitation
- **CVE-2019-12725** Zeroshell unauthenticated RCE

## Legal Disclaimer

**This tool is intended for authorized network security auditing only.**

- Only scan networks you own or have explicit written authorization to test
- Unauthorized scanning of networks you do not own is illegal in most jurisdictions
- Default credential testing may trigger IDS/IPS alerts, account lockouts, or device logging
- This tool does not exploit vulnerabilities it only tests whether default passwords are still in place
- The author is not responsible for misuse of this tool

Always get written permission before scanning. When in doubt, don't scan.

## License

MIT


