---
title: >
  Getting Started
type: "docs"
---

{{< include file="_partials/what-is/_short.md" >}}

Scanned languages/packages:

- Ruby Gems
- Python Packages
- Javascript Node/NPM Packages
- Java Packages
- Golang Modules
- Rust Cargo
- Brew Formula
- Apple Apps
- Cocoapods

## Usage

### Install

```bash
FULL_FILE_NAME=$(echo $(curl -Ls -r 0-1 -o /dev/null -w %{url_effective} https://veertu.com/downloads/runtime-mac-scan) | cut -d/ -f5)
PARTIAL_FILE_NAME=$(echo $FULL_FILE_NAME | awk -F'.zip' '{print $1}')
curl -Ls https://veertu.com/downloads/runtime-mac-scan -o $FULL_FILE_NAME
unzip $FULL_FILE_NAME
rm -f $FULL_FILE_NAME
cd $PARTIAL_FILE_NAME

```

There are two binaries included in the archive.

1. **`runtime-mac-scan-server`** This is the server which will watch for changes/filesystem events. It will run on port 8081 by default (you can change this with `--listen-port`) and exposes a REST API.
2. **`runtime-mac-scan-cli`** This is the CLI which can interact with the server's API.

### Run Server

```bash
❯ ./runtime-mac-scan-server
```

You can then watch the logs with:

```bash
❯ tail -f runtime-mac-scan-server.log
[2022-09-12 20:56:37]  INFO UpdateDB: No meta file scanner.db.meta found
[2022-09-12 20:56:37]  INFO UpdateDB: newest update avaialble for 2022-09-12 19:03:50 +0000 UTC, exisiting date 0001-01-01 00:00:00 +0000 UTC
[2022-09-12 20:56:37]  INFO UpdateDB: downloading update...
[2022-09-12 20:56:37]  INFO Downloading from https://downloads.veertu.com/scanner/scanner.db.2022-09-12T19:03:50Z.zip to /var/folders/cg/zwnjml252tv9d58337f_7xpm0000gn/T/scan-tmpdir4241391468/scanner.db
[2022-09-12 20:56:45]  INFO Downloaded to /var/folders/cg/zwnjml252tv9d58337f_7xpm0000gn/T/scan-tmpdir4241391468/scanner.db
[2022-09-12 20:56:45]  INFO loading DB
[2022-09-12 20:56:45]  INFO GetDBType: bolt
[2022-09-12 20:56:45]  INFO Loaded NVD count 133751
[2022-09-12 20:56:45]  INFO Start listening on port 8081
```

You can also run and get the logs in STDOUT/ERR:

```bash
❯ ./runtime-mac-scan-server --log-to-file=false
[2022-09-13 08:17:34]  INFO UpdateDB: last updated on %!w(time.Time={0 63798606230 <nil>})
[2022-09-13 08:17:43]  INFO UpdateDB: newest update avaialble for 2022-09-12 19:03:50 +0000 UTC, exisiting date 2022-09-12 19:03:50 +0000 UTC
[2022-09-13 08:17:43]  INFO UpdateDB: already has the latest version
[2022-09-13 08:17:43]  INFO loading DB
[2022-09-13 08:17:43]  INFO GetDBType: bolt
[2022-09-13 08:17:47]  INFO Loaded NVD count 133751
[2022-09-13 08:17:47]  INFO Start listening on port 8081
```

### Start / Stop Scanner

You'll then be able to make API calls, or use the CLI tool to start scanning:

```bash
❯ ./runtime-mac-scan-cli
This tool provides an interface to communicate with runtime scanner

Usage:
  runtime-mac-scan-cli [flags]
  runtime-mac-scan-cli [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  report      Report scanning result
  start       Start scanning
  status      Get status
  stop        Stop scanning
  version     Print the version number of rs-cli

Flags:
  -h, --help   help for runtime-mac-scan-cli

Use "runtime-mac-scan-cli [command] --help" for more information about a command.

❯ ./runtime-mac-scan-cli status
State: Stopped

❯ ./runtime-mac-scan-cli start

❯ ./runtime-mac-scan-cli status
State: Running

❯ ./runtime-mac-scan-cli report
No packages discovered
No vulnerabilities found
```

You can see nothing has changed on my computer yet, so nothing was discovered or found. Let's install an older version of jenkins with ruby gem, immediately stop the scanner so we only get the changes for the period of time we installed jenkins, and then generate the report:

```bash
❯ sudo gem install --version 0.6.0 jenkins
Ignoring ffi-1.13.1 because its extensions are not built. Try: gem pristine ffi --version 1.13.1
Fetching jenkins-0.6.0.gem
Successfully installed jenkins-0.6.0
Parsing documentation for jenkins-0.6.0
Installing ri documentation for jenkins-0.6.0
Done installing documentation for jenkins after 0 seconds
1 gem installed

❯ ./runtime-mac-scan-cli stop

❯ tail -f runtime-mac-scan-server.log
[2022-09-12 21:06:04]  INFO UpdateDB: last updated on %!w(time.Time={0 63798606230 <nil>})
[2022-09-12 21:06:04]  INFO UpdateDB: newest update avaialble for 2022-09-12 19:03:50 +0000 UTC, exisiting date 2022-09-12 19:03:50 +0000 UTC
[2022-09-12 21:06:04]  INFO UpdateDB: already has the latest version
[2022-09-12 21:06:04]  INFO loading DB
[2022-09-12 21:06:04]  INFO GetDBType: bolt
[2022-09-12 21:06:05]  INFO Loaded NVD count 133751
[2022-09-12 21:06:05]  INFO Start listening on port 8081

[2022-09-12 21:06:22]  INFO Start listening to fs events

[2022-09-12 21:06:34]  INFO Stop listening to fs events
```

### Generate Report

``` bash
❯ ./runtime-mac-scan-cli report vulnerabilities | head -20
TYPE          NAME              VERSION            VULNERABILITY     SCORE  SEVERITY
gem           actionpack        3.0.1              CVE-2022-27777    6.1    medium
gem           crack             0.1.8              CVE-2013-1800     7.5    high
gem           httparty          0.6.1              CVE-2013-1801     7.5    high
gem           i18n              0.4.2              CVE-2013-4492     4.3    medium
gem           i18n              0.4.2              CVE-2014-10077    7.5    high
gem           i18n              0.4.2              CVE-2020-7791     7.5    high
gem           jenkins           0.6.0              CVE-2012-0324     4.3    medium
gem           jenkins           0.6.0              CVE-2012-0325     4.3    medium
gem           jenkins           0.6.0              CVE-2012-0785     7.8    high
gem           jenkins           0.6.0              CVE-2012-4438     8.8    high
gem           jenkins           0.6.0              CVE-2012-4439     6.1    medium
gem           jenkins           0.6.0              CVE-2012-4440     6.1    medium
gem           jenkins           0.6.0              CVE-2012-4441     6.1    medium
gem           jenkins           0.6.0              CVE-2012-6072     4.3    medium
gem           jenkins           0.6.0              CVE-2012-6073     5.8    medium
gem           jenkins           0.6.0              CVE-2012-6074     3.5    low
gem           jenkins           0.6.0              CVE-2013-0158     2.6    low
gem           jenkins           0.6.0              CVE-2013-0327     6.8    medium
gem           jenkins           0.6.0              CVE-2013-0328     4.3    medium
```

## REST API

An alternative to the included CLI is using the API directly with `curl`.

### /status

Returns the state of the scanning.

```bash
❯ curl http://localhost:8081/status
{"status":"OK","body":{"state":"Stopped"},"error":""}
```

### /start

Starts the scanning.

```bash
❯ curl http://localhost:8081/start
{"status":"OK","body":{"state":"Running"},"error":""}
```

### /stop

Stops the scanning and forces population of packages and vulnerabilities.

```bash
❯ curl http://localhost:8081/stop
{"status":"OK","body":{"state":"Stopped"},"error":""}
```

### /report

Generates and outputs to STDOUT a report of packages and vulnerabilities the scan found while running.

```bash
❯ curl -s http://localhost:8081/report | jq | head -50
{
  "status": "OK",
  "body": {
    "packages": [
      {
        "name": "awesome_print",
        "version": "0.2.1",
        "type": "gem",
        "locations": [
          {
            "path": "/Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/Gemfile.lock"
          }
        ],
        "language": "ruby",
        "licenses": [],
        "cpes": [
          "cpe:2.3:a:awesome-print:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:awesome-print:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:awesome_print:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:awesome_print:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby-lang:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby-lang:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby_lang:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby_lang:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:awesome:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:awesome:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby:awesome_print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:*:awesome-print:0.2.1:*:*:*:*:*:*:*",
          "cpe:2.3:a:*:awesome_print:0.2.1:*:*:*:*:*:*:*"
        ],
        "purl": "pkg:gem/awesome_print@0.2.1",
        "creation_time": "2022-09-12T20:41:02.049576397-04:00",
        "metadata": null
      },
      {
        "name": "builder",
        "version": "2.1.2",
        "type": "gem",
        "locations": [
          {
            "path": "/Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/Gemfile.lock"
          }
        ],
        "language": "ruby",
        "licenses": [],
        "cpes": [
          "cpe:2.3:a:ruby-lang:builder:2.1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:ruby_lang:builder:2.1.2:*:*:*:*:*:*:*",
          "cpe:2.3:a:builder:builder:2.1.2:*:*:*:*:*:*:*",
```

```bash
❯ curl -s http://localhost:8081/report | jq '.body.vulnerabilities' | head -50
[
  {
    "Vulnerability": {
      "MatchedCPEs": [
        {
          "Cpe": {
            "Part": "a",
            "Vendor": "john_nunemaker",
            "Product": "crack",
            "Version": "0\\.1\\.8",
            "Update": "",
            "Edition": "",
            "SWEdition": "",
            "TargetSW": "",
            "TargetHW": "",
            "Other": "",
            "Language": ""
          },
          "Constraint": "= 0.1.8",
          "Version": "0.1.8",
          "MatchType": "Semantic"
        },
        {
          "Cpe": {
            "Part": "a",
            "Vendor": "john_nunemaker",
            "Product": "crack",
            "Version": "",
            "Update": "",
            "Edition": "",
            "SWEdition": "",
            "TargetSW": "",
            "TargetHW": "",
            "Other": "",
            "Language": ""
          },
          "Constraint": "<= 0.3.1",
          "Version": "0.1.8",
          "MatchType": "Semantic"
        }
      ],
      "ID": "CVE-2013-1800",
      "Namespace": "",
      "Score": 7.5,
      "URL": "https://nvd.nist.gov/vuln/detail/CVE-2013-1800",
      "RelatedVulnerabilities": null
    },
    "Package": {
      "ID": "9804960417298599741",
      "Name": "crack",
```

#### /report/packages

Generates and outputs to STDOUT a report of ONLY the packages the scan found while running.

```bash
❯ curl -s http://localhost:8081/report/packages | jq | head -50
{
  "status": "OK",
  "body": [
    {
      "name": "awesome_print",
      "version": "0.2.1",
      "type": "gem",
      "locations": [
        {
          "path": "/Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/Gemfile.lock"
        }
      ],
      "language": "ruby",
      "licenses": [],
      "cpes": [
        "cpe:2.3:a:awesome-print:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:awesome-print:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:awesome_print:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:awesome_print:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby-lang:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby-lang:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby_lang:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby_lang:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:awesome:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:awesome:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby:awesome_print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:*:awesome-print:0.2.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:*:awesome_print:0.2.1:*:*:*:*:*:*:*"
      ],
      "purl": "pkg:gem/awesome_print@0.2.1",
      "creation_time": "2022-09-12T20:41:02.049576397-04:00",
      "metadata": null
    },
    {
      "name": "builder",
      "version": "2.1.2",
      "type": "gem",
      "locations": [
        {
          "path": "/Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/Gemfile.lock"
        }
      ],
      "language": "ruby",
      "licenses": [],
      "cpes": [
        "cpe:2.3:a:ruby-lang:builder:2.1.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby_lang:builder:2.1.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:builder:builder:2.1.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:ruby:builder:2.1.2:*:*:*:*:*:*:*",
```

#### /report/vulnerabilities

Generates and outputs to STDOUT a report of ONLY vulnerabilities the scan found while running.

```bash
❯ curl -s http://localhost:8081/report/vulnerabilities | jq | head -50
{
  "status": "OK",
  "body": [
    {
      "Vulnerability": {
        "MatchedCPEs": [
          {
            "Cpe": {
              "Part": "a",
              "Vendor": "john_nunemaker",
              "Product": "crack",
              "Version": "0\\.1\\.8",
              "Update": "",
              "Edition": "",
              "SWEdition": "",
              "TargetSW": "",
              "TargetHW": "",
              "Other": "",
              "Language": ""
            },
            "Constraint": "= 0.1.8",
            "Version": "0.1.8",
            "MatchType": "Semantic"
          },
          {
            "Cpe": {
              "Part": "a",
              "Vendor": "john_nunemaker",
              "Product": "crack",
              "Version": "",
              "Update": "",
              "Edition": "",
              "SWEdition": "",
              "TargetSW": "",
              "TargetHW": "",
              "Other": "",
              "Language": ""
            },
            "Constraint": "<= 0.3.1",
            "Version": "0.1.8",
            "MatchType": "Semantic"
          }
        ],
        "ID": "CVE-2013-1800",
        "Namespace": "",
        "Score": 7.5,
        "URL": "https://nvd.nist.gov/vuln/detail/CVE-2013-1800",
        "RelatedVulnerabilities": null
      },
      "Package": {
```

#### ?fromTime=

Reports endpoints allow setting the `fromTime` to isolate packages and vulnerabilities from a specific time.

**The time must be in RFC3339.** On MacOS, you can generate this time using `date -u +%Y-%m-%dT%H:%M:%SZ`.

```bash
❯ curl -s http://localhost:8081/report/vulnerabilities\?fromTime\=2022-09-13T12:47:33Z | jq | head -50
{
  "status": "OK",
  "body": [
    {
      "Vulnerability": {
        "MatchedCPEs": [
          {
            "Cpe": {
              "Part": "a",
              "Vendor": "john_nunemaker",
              "Product": "crack",
              "Version": "0\\.1\\.8",
              "Update": "",
              "Edition": "",
              "SWEdition": "",
              "TargetSW": "",
              "TargetHW": "",
              "Other": "",
              "Language": ""
            },
            "Constraint": "= 0.1.8",
            "Version": "0.1.8",
            "MatchType": "Semantic"
          },
          {
            "Cpe": {
              "Part": "a",
              "Vendor": "john_nunemaker",
              "Product": "crack",
              "Version": "",
              "Update": "",
              "Edition": "",
              "SWEdition": "",
              "TargetSW": "",
              "TargetHW": "",
              "Other": "",
              "Language": ""
            },
            "Constraint": "<= 0.3.1",
            "Version": "0.1.8",
            "MatchType": "Semantic"
          }
        ],
        "ID": "CVE-2013-1800",
        "Namespace": "",
        "Score": 7.5,
        "URL": "https://nvd.nist.gov/vuln/detail/CVE-2013-1800",
        "RelatedVulnerabilities": null
      },
      "Package": {
```
