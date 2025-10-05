# OCSP Check (CLI Tool)

CLI (Command-Line-Interface) Tool to check the OCSP status of a .p12/.mobileprovision file.

Version: `1.1`

___

## Usage:

`Usage: ./tool.sh [--json] [--prettify-json] [--password <password>] --type <ocsp|info> --p12 <file.p12> --mp <file.mobileprovision>`

## Requirements:

- **OpenSSL & Python**
  
> `sudo apt install openssl python3` (Debian/Ubuntu)
>
> `sudo dnf install openssl python3` (Fedora)
>
> `sudo yum install openssl python3` (CentOS/RHEL 7)
>
> `sudo dnf install openssl python3` (CentOS/RHEL 8+)
>
> `sudo pacman -Syu openssl python --noconfirm` (Arch Linux)
>
> `sudo zypper install openssl python3` (openSUSE)
>
> `apk add openssl python3` (Alpine Linux (ISH App on iOS))
>
> `pkg install openssl python` (Termux App Android)


## Installing:

- **Copy/Download/Clone** the .sh file into your System (Use the iSH app for iOS, Termux for Android)
- Run `chmod +x tool.sh` to give the Script Permission to run
- Run any command you want to example: `./tool.sh --type ocsp --p12 Cert.p12 --mp Profile.mobileprovision --password 123456 --json --prettify-json`

**Output:**


```json
{
  "p12": {
    "ocsp_url": "http://ocsp.apple.com/ocsp03-wwdrg304",
    "status": "good",
    "this_update": "Oct  5 12:02:39 2025 GMT",
    "next_update": "Oct  6 00:02:38 2025 GMT"
  },
  "mobileprovision": {
    "ocsp_url": "http://ocsp.apple.com/ocsp03-wwdrg304",
    "status": "good"
  }
}
```


## Additional Information:

There is also a type called **info** use it like this:

`./tool.sh --type info --p12 Cert.p12 --mp Profile.mobileprovision --password 123456 --json --prettify-json`

**Output:**


```json
{
  "p12": {
    "uid": "54BVG7X3DK",
    "cn": "Apple Development: Raviza Shah (KGTMBA4B75)",
    "ou": "8TVMC6U8D9",
    "o": "Raviza Shah",
    "c": "US",
    "issuer": "CN=Apple Worldwide Developer Relations Certification Authority, OU=G3, O=Apple Inc., C=US",
    "serial": "149095fafb7067e3c3eaeefac1f38b15",
    "not_before": "Oct  3 10:44:37 2024 GMT",
    "not_after": "Oct  3 10:44:36 2025 GMT",
    "signature_algorithm": "sha256WithRSAEncryption",
    "public_key_algorithm": "rsaEncryption",
    "key_size": "2048",
    "key_usage": "Digital Signature",
    "extended_key_usage": "Code Signing"
  },
  "mobileprovision": {
    "appidname": "Wildcard",
    "applicationidentifierprefix": "8TVMC6U8D9",
    "platform": ["iOS", "xrOS", "visionOS"],
    "isxcodemanaged": false,
    "ppqcheck": true,
    "entitlements_com_apple_developer_default_data_protection": "NSFileProtectionComplete",
    "entitlements_application_identifier": "8TVMC6U8D9.*",
    "entitlements_get_task_allow": true,
    "entitlements_com_apple_developer_team_identifier": "8TVMC6U8D9",
    "entitlements_com_apple_developer_ubiquity_kvstore_identifier": "8TVMC6U8D9.*",
    "entitlements_inter_app_audio": true,
    "entitlements_com_apple_developer_siri": true,
    "name": "00008101-00012d483e41001e_wildcard_dev",
    "provisioneddevices": "00008101-00012D483E41001E",
    "teamidentifier": "8TVMC6U8D9",
    "teamname": "Raviza Shah",
    "timetolive": 365,
    "uuid": "f1b84055-d3a3-4c97-bcba-0d2485393bec",
    "version": 1
  }
}
```




