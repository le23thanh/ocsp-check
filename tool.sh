#!/bin/bash
set -e

usage() {
    echo "Usage: $0 [--json] [--password <password>] --type <ocsp|info> --p12 <file.p12> --mp <file.mobileprovision>"
    exit 1
}

JSON_MODE=false
P12_FILE=""
MP_FILE=""
PASSWORD=""
TYPE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --json) JSON_MODE=true; shift ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --type) TYPE="$2"; shift 2 ;;
        --p12) P12_FILE="$2"; shift 2 ;;
        --mp|--mobileprovision) MP_FILE="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[[ -z "$P12_FILE" && -z "$MP_FILE" ]] && usage
[[ -z "$TYPE" ]] && usage
[[ "$TYPE" != "ocsp" && "$TYPE" != "info" ]] && usage

RANDOM_FOLDER="certificates/$(openssl rand -hex 8)"
mkdir -p "$RANDOM_FOLDER"

[[ "$JSON_MODE" == true ]] && echo "{"
FIRST=true

if [[ -n "$P12_FILE" && -f "$P12_FILE" ]]; then
    openssl pkcs12 -legacy -in "$P12_FILE" -clcerts -nokeys -out "$RANDOM_FOLDER/p12.pem" -passin "pass:$PASSWORD" 2>/dev/null || \
    openssl pkcs12 -in "$P12_FILE" -clcerts -nokeys -out "$RANDOM_FOLDER/p12.pem" -passin "pass:$PASSWORD" 2>/dev/null
    
    if [[ "$TYPE" == "ocsp" ]]; then
        OCSP_URL=$(openssl x509 -in "$RANDOM_FOLDER/p12.pem" -noout -ocsp_uri)
        
        curl -s -o "$RANDOM_FOLDER/issuer.cer" "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"
        openssl x509 -inform DER -in "$RANDOM_FOLDER/issuer.cer" -out "$RANDOM_FOLDER/issuer.pem"
        
        OCSP_OUTPUT=$(openssl ocsp -issuer "$RANDOM_FOLDER/issuer.pem" -cert "$RANDOM_FOLDER/p12.pem" -url "$OCSP_URL" -CAfile "$RANDOM_FOLDER/issuer.pem" -noverify 2>&1 || true)
        STATUS=$(echo "$OCSP_OUTPUT" | grep -o "p12.pem: [a-z]*" | awk '{print $2}' || echo "unknown")
        THIS_UPDATE=$(echo "$OCSP_OUTPUT" | grep "This Update:" | sed 's/.*This Update: //')
        NEXT_UPDATE=$(echo "$OCSP_OUTPUT" | grep "Next Update:" | sed 's/.*Next Update: //')
        
        if [[ "$JSON_MODE" == true ]]; then
            echo "  \"p12\": {\"ocsp_url\": \"$OCSP_URL\", \"status\": \"$STATUS\", \"this_update\": \"$THIS_UPDATE\", \"next_update\": \"$NEXT_UPDATE\"}"
        else
            echo "P12 OCSP: $STATUS | $OCSP_URL"
        fi
    else
        openssl x509 -in "$RANDOM_FOLDER/p12.pem" -noout -text > "$RANDOM_FOLDER/p12_full.txt"
        
        cat > "$RANDOM_FOLDER/parse_cert.py" << 'PYEND'
import re
import json
import sys

with open(sys.argv[1], 'r') as f:
    cert_text = f.read()

data = {}

subject = re.search(r'Subject: (.+)', cert_text)
if subject:
    for part in subject.group(1).split(','):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            data[k.strip().lower().replace(' ', '_')] = v.strip()

issuer = re.search(r'Issuer: (.+)', cert_text)
if issuer:
    data['issuer'] = issuer.group(1).strip()

serial = re.search(r'Serial Number:\s*\n?\s*([0-9a-f:]+)', cert_text, re.IGNORECASE)
if serial:
    data['serial'] = serial.group(1).replace(':', '').strip()

validity = re.findall(r'(Not Before|Not After)\s*:\s*(.+)', cert_text)
for match in validity:
    key = match[0].lower().replace(' ', '_')
    data[key] = match[1].strip()

sig_algo = re.search(r'Signature Algorithm: (.+)', cert_text)
if sig_algo:
    data['signature_algorithm'] = sig_algo.group(1).strip()

pubkey = re.search(r'Public Key Algorithm: (.+)', cert_text)
if pubkey:
    data['public_key_algorithm'] = pubkey.group(1).strip()

keysize = re.search(r'Public-Key: \((\d+) bit\)', cert_text)
if keysize:
    data['key_size'] = keysize.group(1)

key_usage = re.search(r'X509v3 Key Usage:.*?\n\s+(.+)', cert_text)
if key_usage:
    data['key_usage'] = key_usage.group(1).strip()

ext_key_usage = re.search(r'X509v3 Extended Key Usage:.*?\n\s+(.+)', cert_text)
if ext_key_usage:
    data['extended_key_usage'] = ext_key_usage.group(1).strip()

if len(sys.argv) > 2 and sys.argv[2] == 'true':
    print("  \"p12\":", json.dumps(data))
else:
    for k, v in data.items():
        print(f"{k}: {v}")
PYEND

        python3 "$RANDOM_FOLDER/parse_cert.py" "$RANDOM_FOLDER/p12_full.txt" "$JSON_MODE"
    fi
    FIRST=false
fi

if [[ -n "$MP_FILE" && -f "$MP_FILE" ]]; then
    security cms -D -i "$MP_FILE" > "$RANDOM_FOLDER/profile.plist"
    
    [[ "$JSON_MODE" == true && "$FIRST" == false ]] && echo "  ,"
    
    if [[ "$TYPE" == "ocsp" ]]; then
        CERT_BASE64=$(plutil -extract DeveloperCertificates.0 xml1 -o - "$RANDOM_FOLDER/profile.plist" | xmllint --xpath "string(//data)" -)
        echo "$CERT_BASE64" | base64 -d > "$RANDOM_FOLDER/mp.pem"
        
        OCSP_URL=$(openssl x509 -in "$RANDOM_FOLDER/mp.pem" -noout -ocsp_uri)
        curl -s -o "$RANDOM_FOLDER/issuer.cer" "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"
        openssl x509 -inform DER -in "$RANDOM_FOLDER/issuer.cer" -out "$RANDOM_FOLDER/issuer.pem"
        
        OCSP_OUTPUT=$(openssl ocsp -issuer "$RANDOM_FOLDER/issuer.pem" -cert "$RANDOM_FOLDER/mp.pem" -url "$OCSP_URL" -CAfile "$RANDOM_FOLDER/issuer.pem" -noverify 2>&1 || true)
        STATUS=$(echo "$OCSP_OUTPUT" | grep -o "mp.pem: [a-z]*" | awk '{print $2}' || echo "unknown")
        
        if [[ "$JSON_MODE" == true ]]; then
            echo "  \"mobileprovision\": {\"ocsp_url\": \"$OCSP_URL\", \"status\": \"$STATUS\"}"
        else
            echo "MP OCSP: $STATUS | $OCSP_URL"
        fi
    else
        cat > "$RANDOM_FOLDER/parse_plist.py" << 'PYEND'
import plistlib
import json
import sys

try:
    with open(sys.argv[1], 'rb') as f:
        plist = plistlib.load(f)
except:
    print("{}" if len(sys.argv) > 2 and sys.argv[2] == 'true' else "")
    sys.exit(0)

data = {}

for key, value in plist.items():
    new_key = key.replace(' ', '_').replace('-', '_').lower()
    
    if isinstance(value, (str, int, bool)):
        data[new_key] = value
    elif isinstance(value, list) and len(value) > 0:
        if isinstance(value[0], (str, int, bool)):
            if len(value) == 1:
                data[new_key] = value[0]
            else:
                data[new_key] = value
    elif isinstance(value, dict):
        for k, v in value.items():
            sub_key = f"{new_key}_{k.replace('-', '_').replace('.', '_')}"
            if isinstance(v, (str, int, bool)):
                data[sub_key] = v

if len(sys.argv) > 2 and sys.argv[2] == 'true':
    print("  \"mobileprovision\":", json.dumps(data, default=str))
else:
    for k, v in data.items():
        print(f"{k}: {v}")
PYEND

        python3 "$RANDOM_FOLDER/parse_plist.py" "$RANDOM_FOLDER/profile.plist" "$JSON_MODE"
    fi
fi

[[ "$JSON_MODE" == true ]] && echo "}"
