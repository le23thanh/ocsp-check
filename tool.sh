#!/bin/bash
set -e

usage() {
    echo "Usage: $0 [--json] [--prettify-json] [--password <password>] --type <ocsp|info> --p12 <file.p12> [--mp <file.mobileprovision>]"
    exit 1
}

JSON_MODE=false
PRETTY_JSON=false
P12_FILE=""
MP_FILE=""
PASSWORD=""
TYPE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --json) JSON_MODE=true; shift ;;
        --prettify-json) PRETTY_JSON=true; shift ;;
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

# Detect if running on macOS
IS_MACOS=false
if [[ "$(uname)" == "Darwin" ]]; then
    IS_MACOS=true
fi

# Collect all JSON outputs in a temporary file if in JSON mode
JSON_OUTPUT=""

if [[ -n "$P12_FILE" && -f "$P12_FILE" ]]; then
    if [[ "$IS_MACOS" == true ]]; then
        # macOS: Use Python cryptography library
        cat > "$RANDOM_FOLDER/check_p12.py" << 'PYEND'
import sys
import subprocess
import json
import warnings
import traceback
warnings.filterwarnings('ignore')

try:
    from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
    import tempfile
    import os
except ImportError as e:
    print(json.dumps({'error': f'Missing required library: {str(e)}. Install with: pip3 install cryptography'}))
    sys.exit(0)

def get_ocsp_url(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                return desc.access_location.value
    except:
        pass
    return None

def get_issuer_url(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                return desc.access_location.value
    except:
        pass
    return None

def check_ocsp(cert_pem, issuer_pem, ocsp_url, serial_hex):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
        cert_file.write(cert_pem)
        cert_path = cert_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as issuer_file:
        issuer_file.write(issuer_pem)
        issuer_path = issuer_file.name
    
    try:
        result = subprocess.run(
            ['openssl', 'ocsp', '-issuer', issuer_path, '-serial', f'0x{serial_hex}', 
             '-url', ocsp_url, '-CAfile', issuer_path, '-no_nonce'],
            capture_output=True, text=True, timeout=10
        )
        
        output = result.stdout + result.stderr
        
        if 'good' in output.lower():
            status = 'good'
        elif 'revoked' in output.lower():
            status = 'revoked'
        else:
            status = 'unknown'
        
        this_update = ''
        next_update = ''
        revoked_time = ''
        
        for line in output.split('\n'):
            if 'This Update:' in line:
                this_update = line.split('This Update:')[1].strip()
            elif 'Next Update:' in line:
                next_update = line.split('Next Update:')[1].strip()
            elif 'Revocation Time:' in line:
                revoked_time = line.split('Revocation Time:')[1].strip()
        
        return {
            'status': status,
            'this_update': this_update,
            'next_update': next_update,
            'revoked_time': revoked_time,
            'raw_output': output
        }
    finally:
        os.unlink(cert_path)
        os.unlink(issuer_path)

try:
    p12_file = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else ''
    check_type = sys.argv[3] if len(sys.argv) > 3 else 'ocsp'
    
    # Read P12 file
    try:
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
    except Exception as e:
        print(json.dumps({'error': f'Cannot read P12 file: {str(e)}'}))
        sys.exit(0)
    
    # Try to load P12 with password
    password_bytes = password.encode('utf-8')
    try:
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, password_bytes, default_backend()
        )
    except Exception as e:
        # Try with empty password
        try:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, None, default_backend()
            )
        except Exception as e2:
            print(json.dumps({'error': f'Cannot decrypt P12 file. Wrong password? Original error: {str(e)}'}))
            sys.exit(0)
    
    if not certificate:
        print(json.dumps({'error': 'No certificate found in P12 file'}))
        sys.exit(0)
    
    cert_pem = certificate.public_bytes(Encoding.PEM).decode('utf-8')
    serial_hex = format(certificate.serial_number, 'x')
    
    if check_type == 'ocsp':
        ocsp_url = get_ocsp_url(certificate)
        if not ocsp_url:
            print(json.dumps({'error': 'No OCSP URL found in certificate'}))
            sys.exit(0)
        
        issuer_url = get_issuer_url(certificate)
        if not issuer_url:
            print(json.dumps({'error': 'No issuer URL found in certificate'}))
            sys.exit(0)
        
        import urllib.request
        try:
            issuer_der = urllib.request.urlopen(issuer_url).read()
            issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
            issuer_pem = issuer_cert.public_bytes(Encoding.PEM).decode('utf-8')
        except Exception as e:
            print(json.dumps({'error': f'Cannot download issuer certificate: {str(e)}'}))
            sys.exit(0)
        
        ocsp_result = check_ocsp(cert_pem, issuer_pem, ocsp_url, serial_hex)
        
        result = {
            'ocsp_url': ocsp_url,
            'status': ocsp_result['status'],
            'serial': serial_hex,
            'this_update': ocsp_result['this_update'],
            'next_update': ocsp_result['next_update']
        }
        
        if ocsp_result['revoked_time']:
            result['revocation_time'] = ocsp_result['revoked_time']
        
        if ocsp_result['status'] == 'revoked':
            raw_output = ocsp_result['raw_output']
            revoked_by = "Unknown"
            
            if 'Revocation Reason:' in raw_output:
                if 'keyCompromise' in raw_output or 'Key Compromise' in raw_output:
                    revoked_by = "Certificate holder (key compromised)"
                elif 'cessationOfOperation' in raw_output or 'Cessation' in raw_output:
                    revoked_by = "Certificate holder (ceased operations)"
                elif 'superseded' in raw_output or 'Superseded' in raw_output:
                    revoked_by = "Certificate holder (superseded by new certificate)"
                elif 'affiliationChanged' in raw_output or 'Affiliation' in raw_output:
                    revoked_by = "Apple (affiliation changed)"
                elif 'certificateHold' in raw_output or 'Certificate Hold' in raw_output:
                    revoked_by = "Apple (temporary hold)"
                elif 'privilegeWithdrawn' in raw_output or 'Privilege Withdrawn' in raw_output:
                    revoked_by = "Apple (privileges withdrawn)"
                else:
                    revoked_by = "Apple or certificate holder"
            else:
                revoked_by = "Apple or certificate holder (reason not specified)"
            
            result['revoked_by'] = revoked_by
        
        print(json.dumps(result))
    else:
        subject_dict = {}
        for attr in certificate.subject:
            key = attr.oid._name.lower().replace(' ', '_')
            subject_dict[key] = attr.value
        
        issuer_str = ', '.join([f"{attr.oid._name}={attr.value}" for attr in certificate.issuer])
        
        result = {
            **subject_dict,
            'issuer': issuer_str,
            'serial': serial_hex,
            'not_before': str(certificate.not_valid_before_utc),
            'not_after': str(certificate.not_valid_after_utc),
        }
        
        try:
            pub_key = certificate.public_key()
            result['key_size'] = str(pub_key.key_size)
        except:
            pass
        
        try:
            result['signature_algorithm'] = certificate.signature_algorithm_oid._name
        except:
            pass
        
        print(json.dumps(result))
        
except Exception as e:
    error_msg = f'Unexpected error: {str(e)}\n{traceback.format_exc()}'
    print(json.dumps({'error': error_msg}))
    sys.exit(0)
PYEND

        P12_RESULT=$(python3 "$RANDOM_FOLDER/check_p12.py" "$P12_FILE" "$PASSWORD" "$TYPE" 2>&1)
        
        if [[ "$JSON_MODE" == true ]]; then
            JSON_OUTPUT="\"p12\": $P12_RESULT"
        else
            # Check if it's an error or success
            if echo "$P12_RESULT" | python3 -c "import sys, json; d=json.loads(sys.stdin.read()); sys.exit(0 if 'error' not in d else 1)" 2>/dev/null; then
              if [[ "$TYPE" == "ocsp" ]]; then
                    echo "$P12_RESULT" | python3 -c 'import sys, json; d = json.load(sys.stdin); print("P12 OCSP:", d.get("status", "unknown"), "|", d.get("ocsp_url", "N/A")); print("  Serial:", d.get("serial", "N/A")); d.get("this_update") and print("  This Update:", d["this_update"]); d.get("next_update") and print("  Next Update:", d["next_update"]); d.get("revocation_time") and print("  Revocation Time:", d["revocation_time"]); d.get("revoked_by") and print("  Revoked By:", d["revoked_by"])'
                else
                    echo "$P12_RESULT" | python3 -c 'import sys, json; d = json.load(sys.stdin); [print(k + ":", v) for k, v in d.items()]'
                fi
           else
                echo "$P12_RESULT" | python3 -c 'import sys, json; d = json.load(sys.stdin); print("Error:", d.get("error", "Unknown error"))'
            fi
        fi
    else
     # Linux: Use original OpenSSL approach with better error handling
        # Try simple extraction first, then with -legacy
        if ! openssl pkcs12 -in "$P12_FILE" -nokeys -out "$RANDOM_FOLDER/p12.pem" -passin "pass:$PASSWORD" 2>/dev/null; then
            if ! openssl pkcs12 -legacy -in "$P12_FILE" -nokeys -out "$RANDOM_FOLDER/p12.pem" -passin "pass:$PASSWORD" 2>/dev/null; then
                # Try with empty password
                if ! openssl pkcs12 -in "$P12_FILE" -nokeys -out "$RANDOM_FOLDER/p12.pem" -passin "pass:" 2>/dev/null; then
                    if [[ "$JSON_MODE" == true ]]; then
                        JSON_OUTPUT="\"p12\": {\"error\": \"Cannot decrypt P12 file. Wrong password?\"}"
                    else
                        echo "Error: Cannot decrypt P12 file. Wrong password?"
                    fi
                    rm -rf "$RANDOM_FOLDER"
                    [[ "$JSON_MODE" == true ]] && echo "{$JSON_OUTPUT}"
                    exit 1
                fi
            fi
        fi
        
        # Verify certificate was extracted
        if [[ ! -s "$RANDOM_FOLDER/p12.pem" ]] || ! grep -q "BEGIN CERTIFICATE" "$RANDOM_FOLDER/p12.pem"; then
            if [[ "$JSON_MODE" == true ]]; then
                JSON_OUTPUT="\"p12\": {\"error\": \"No certificate found in P12 file\"}"
            else
                echo "Error: No certificate found in P12 file"
            fi
            rm -rf "$RANDOM_FOLDER"
            [[ "$JSON_MODE" == true ]] && echo "{$JSON_OUTPUT}"
            exit 1
        fi
        
        if [[ "$TYPE" == "ocsp" ]]; then
            OCSP_URL=$(openssl x509 -in "$RANDOM_FOLDER/p12.pem" -noout -ocsp_uri)
            
            if [[ -z "$OCSP_URL" ]]; then
                if [[ "$JSON_MODE" == true ]]; then
                    JSON_OUTPUT="\"p12\": {\"error\": \"No OCSP URL found in certificate\"}"
                else
                    echo "Error: No OCSP URL found in certificate"
                fi
            else
                # Download issuer certificate
                curl -s -o "$RANDOM_FOLDER/issuer.cer" "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer" || \
                curl -s -o "$RANDOM_FOLDER/issuer.cer" "https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer"
                
                if [[ -f "$RANDOM_FOLDER/issuer.cer" ]]; then
                    openssl x509 -inform DER -in "$RANDOM_FOLDER/issuer.cer" -out "$RANDOM_FOLDER/issuer.pem" 2>/dev/null || true
                fi
                
              # Perform OCSP check
                OCSP_OUTPUT=$(openssl ocsp -issuer "$RANDOM_FOLDER/issuer.pem" -cert "$RANDOM_FOLDER/p12.pem" -url "$OCSP_URL" -CAfile "$RANDOM_FOLDER/issuer.pem" -noverify 2>&1 || true)
                STATUS=$(echo "$OCSP_OUTPUT" | grep -o "p12.pem: [a-z]*" | awk '{print $2}' || echo "unknown")
                THIS_UPDATE=$(echo "$OCSP_OUTPUT" | grep "This Update:" | sed 's/.*This Update: //')
                NEXT_UPDATE=$(echo "$OCSP_OUTPUT" | grep "Next Update:" | sed 's/.*Next Update: //')
                REVOKED_TIME=$(echo "$OCSP_OUTPUT" | grep "Revocation Time:" | sed 's/.*Revocation Time: //')
                
                if [[ "$JSON_MODE" == true ]]; then
                    JSON_OUTPUT="\"p12\": {\"ocsp_url\": \"$OCSP_URL\", \"status\": \"$STATUS\", \"this_update\": \"$THIS_UPDATE\", \"next_update\": \"$NEXT_UPDATE\""
                    
                    if [[ -n "$REVOKED_TIME" ]]; then
                        JSON_OUTPUT="${JSON_OUTPUT}, \"revocation_time\": \"$REVOKED_TIME\""
                        
                        # Determine who revoked
                        REVOKED_BY="Unknown"
                        if echo "$OCSP_OUTPUT" | grep -q "keyCompromise"; then
                            REVOKED_BY="Certificate holder (key compromised)"
                        elif echo "$OCSP_OUTPUT" | grep -q "cessationOfOperation"; then
                            REVOKED_BY="Certificate holder (ceased operations)"
                        elif echo "$OCSP_OUTPUT" | grep -q "superseded"; then
                            REVOKED_BY="Certificate holder (superseded by new certificate)"
                        elif echo "$OCSP_OUTPUT" | grep -q "affiliationChanged"; then
                            REVOKED_BY="Apple (affiliation changed)"
                        elif echo "$OCSP_OUTPUT" | grep -q "certificateHold"; then
                            REVOKED_BY="Apple (temporary hold)"
                        elif echo "$OCSP_OUTPUT" | grep -q "privilegeWithdrawn"; then
                            REVOKED_BY="Apple (privileges withdrawn)"
                        else
                            REVOKED_BY="Apple or certificate holder (reason not specified)"
                        fi
                        
                        JSON_OUTPUT="${JSON_OUTPUT}, \"revoked_by\": \"$REVOKED_BY\""
                    fi
                    
                    JSON_OUTPUT="${JSON_OUTPUT}}"
               else
                    echo "P12 OCSP: $STATUS | $OCSP_URL"
                    [[ -n "$THIS_UPDATE" ]] && echo "  This Update: $THIS_UPDATE"
                    [[ -n "$NEXT_UPDATE" ]] && echo "  Next Update: $NEXT_UPDATE"
                    [[ -n "$REVOKED_TIME" ]] && echo "  Revocation Time: $REVOKED_TIME"
                fi
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

print(json.dumps(data))
PYEND

            P12_DATA=$(python3 "$RANDOM_FOLDER/parse_cert.py" "$RANDOM_FOLDER/p12_full.txt")
            
            if [[ "$JSON_MODE" == true ]]; then
                JSON_OUTPUT="\"p12\": $P12_DATA"
            else
                echo "$P12_DATA" | python3 -c 'import sys, json; d = json.load(sys.stdin); [print(f"{k}: {v}") for k, v in d.items()]'
            fi
        fi
    fi
fi

if [[ -n "$MP_FILE" && -f "$MP_FILE" ]]; then
    security cms -D -i "$MP_FILE" > "$RANDOM_FOLDER/profile.plist" 2>/dev/null || {
        if [[ "$JSON_MODE" == true ]]; then
            [[ -n "$JSON_OUTPUT" ]] && JSON_OUTPUT+=", "
            JSON_OUTPUT+="\"mobileprovision\": {\"error\": \"Cannot decode mobileprovision file\"}"
        else
            echo "Error: Cannot decode mobileprovision file"
        fi
        MP_FILE=""
    }
fi

if [[ -n "$MP_FILE" && -f "$RANDOM_FOLDER/profile.plist" ]]; then
    if [[ "$TYPE" == "ocsp" ]]; then
        CERT_BASE64=$(plutil -extract DeveloperCertificates.0 xml1 -o - "$RANDOM_FOLDER/profile.plist" 2>/dev/null | xmllint --xpath "string(//data)" - 2>/dev/null)
        
        if [[ -n "$CERT_BASE64" ]]; then
            echo "$CERT_BASE64" | base64 -d > "$RANDOM_FOLDER/mp.pem" 2>/dev/null
            
            OCSP_URL=$(openssl x509 -in "$RANDOM_FOLDER/mp.pem" -noout -ocsp_uri 2>/dev/null)
            curl -s -o "$RANDOM_FOLDER/issuer.cer" "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"
            openssl x509 -inform DER -in "$RANDOM_FOLDER/issuer.cer" -out "$RANDOM_FOLDER/issuer.pem" 2>/dev/null
            
            OCSP_OUTPUT=$(openssl ocsp -issuer "$RANDOM_FOLDER/issuer.pem" -cert "$RANDOM_FOLDER/mp.pem" -url "$OCSP_URL" -CAfile "$RANDOM_FOLDER/issuer.pem" -noverify 2>&1 || true)
            STATUS=$(echo "$OCSP_OUTPUT" | grep -o "mp.pem: [a-z]*" | awk '{print $2}' || echo "unknown")
            
            if [[ "$JSON_MODE" == true ]]; then
                [[ -n "$JSON_OUTPUT" ]] && JSON_OUTPUT+=", "
                JSON_OUTPUT+="\"mobileprovision\": {\"ocsp_url\": \"$OCSP_URL\", \"status\": \"$STATUS\"}"
            else
                echo "MP OCSP: $STATUS | $OCSP_URL"
            fi
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
    print("{}")
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

print(json.dumps(data, default=str))
PYEND

        MP_DATA=$(python3 "$RANDOM_FOLDER/parse_plist.py" "$RANDOM_FOLDER/profile.plist")
        
        if [[ "$JSON_MODE" == true ]]; then
            [[ -n "$JSON_OUTPUT" ]] && JSON_OUTPUT+=", "
            JSON_OUTPUT+="\"mobileprovision\": $MP_DATA"
        else
            echo "$MP_DATA" | python3 -c 'import sys, json; d = json.load(sys.stdin); [print(f"{k}: {v}") for k, v in d.items()]'
        fi
    fi
fi

# Final JSON output assembly and optional prettification
if [[ "$JSON_MODE" == true ]]; then
    FINAL_JSON="{${JSON_OUTPUT:-}}"
    if [[ "$PRETTY_JSON" == true ]]; then
        echo "$FINAL_JSON" | python3 -c 'import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))'
    else
        echo "$FINAL_JSON"
    fi
fi

# Cleanup
rm -rf "$RANDOM_FOLDER"