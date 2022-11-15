---
title: >
  Getting Started
type: "docs"
---

{{< include file="_partials/what-is/_short.md" >}}

## Usage

### Install

```bash
FULL_FILE_NAME=$(echo $(curl -Ls -r 0-1 -o /dev/null -w %{url_effective} https://veertu.com/downloads/mac-scan) | cut -d/ -f5)
curl -S -L -o ./$FULL_FILE_NAME https://veertu.com/downloads/mac-scan
sudo installer -pkg $FULL_FILE_NAME -tgt /
```

Once the mac-scan package has been installed, the binaries and other mac-scan related data is stored under `/Library/Application Support/mac-scan`.

```bash
❯ sudo pkgutil --pkg-info com.veertu.mac-scan
package-id: com.veertu.mac-scan
version: 0.2.0
volume: /
location: /
install-time: 1666209750

❯ sudo pkgutil --files com.veertu.mac-scan
Library
Library/Application Support
Library/Application Support/mac-scan
Library/Application Support/mac-scan/bin
Library/Application Support/mac-scan/bin/mac-scan-cli
Library/Application Support/mac-scan/bin/mac-scand
Library/Application Support/mac-scan/mac-scan.yml
Library/Application Support/mac-scan/uninstall.sh
Library/LaunchDaemons
Library/LaunchDaemons/com.veertu.mac-scan.plist

❯ sudo launchctl print system/com.veertu.mac-scan
. . .
        path = /Library/LaunchDaemons/com.veertu.mac-scan.plist
        state = running
        program = /Library/Application Support/mac-scan/bin/mac-scand
        arguments = {
                /Library/Application Support/mac-scan/bin/mac-scand
                -c
                /Library/Application Support/mac-scan/mac-scan.yml
        }
. . .

❯ ls -laht /usr/local/bin | grep mac-scan
lrwxr-xr-x    1 root          admin    54B Oct 19 16:06 mac-scan-cli -> /Library/Application Support/mac-scan/bin/mac-scan-cli
```

As you can see, the plist will keep the `mac-scand` running on the host and available for the `mac-scan-cli` or even direct API calls.

{{< hint info >}}
Note that there is an uninstaller script:

```bash
❯ sudo /Library/Application\ Support/mac-scan/uninstall.sh
The following packages will be REMOVED:
  mac-scan-0.2.0
Do you wish to continue [Y/n]?Y
mac-scan uninstall process started...
[1/3] [DONE] Successfully deleted shortcut links
[2/3] [DONE] Successfully deleted mac-scan info
[3/3] [DONE] Successfully deleted mac-scan
mac-scan uninstall process finished!
```
{{< /hint >}}

### Configure

Within the mac-scan application support directory is the `mac-scan.yml`. This can be modified to change logging locations as well as the API port (defaulting to 8081).

```bash
❯ cat /Library/Application\ Support/mac-scan/mac-scan.yml 
log-level: "logrus.InfoLevel"
log-to-file: true
log-file: "/Library/Logs/mac-scan/mac-scan.log"
vuln-db-path: "/Library/Application Support/mac-scan/scanner.db"
disable-auto-update: false
ignore-packages:
  - "cpe:/a:apple:icloud:1.0"
listen-port: 8081
db-backend-path: "/Library/Application Support/mac-scan/pkgstore.db"
```

### Generate Report

```bash
❯ mac-scan-cli report --help                    
Display scanning results from the beginning of the last start command or user provided date

Usage:
  mac-scan-cli report [flags]
  mac-scan-cli report [command]

Available Commands:
  packages        Report detected packages
  reset           Reset scanning results
  vulnerabilities Report detected vulnerabilities

Flags:
  -h, --help                   help for report
  -f, --report-format string   report output format, formats=[json table] (default "table")
  -t, --timestamp string       report packages newer than specified time (RFC3339 format)

Use "mac-scan-cli report [command] --help" for more information about a command.
```

### Scan Modes

#### Full Scan

```bash
❯ mac-scan-cli       
This tool provides an interface to communicate with the mac-scand API

Usage:
  mac-scan-cli [flags]
  mac-scan-cli [command]

Available Commands:
  background-watch Watch for file system changes in the background
  completion       Generate the autocompletion script for the specified shell
  fullscan         Catalog all the packages on the disk
  help             Help about any command
  license          License show/activate
  report           Report scanning result
  status           Get status
  version          Print the version number of rs-cli

Flags:
  -h, --help   help for mac-scan-cli

Use "mac-scan-cli [command] --help" for more information about a command.

❯ mac-scan-cli report
No packages discovered
No vulnerabilities found

❯ mac-scan-cli fullscan

❯ mac-scan-cli report | head -20 
TYPE            NAME                                                                           VERSION                                                                                           
brew            amazon-ecs-cli                                                                 1.21.0                                                                                             
brew            anka-scripts                                                                   c2c6cc19c6406af1bc3b522a14c3884644488954                                                           
brew            ansible                                                                        6.2.0                                                                                              
brew            ansible-lint                                                                   6.4.0                                                                                              
brew            aom                                                                            3.5.0_1                                                                                            
brew            apr                                                                            1.7.0_2                                                                                            
brew            apr                                                                            1.7.0_3                                                                                            
brew            apr-util                                                                       1.6.1_4                                                                                            
brew            augeas                                                                         1.12.0_1                                                                                           
brew            autoconf                                                                       2.71                                                                                               
brew            automake                                                                       1.16.5                                                                                             
brew            aws-iam-authenticator                                                          0.5.9                                                                                              
brew            awscli                                                                         2.7.23                                                                                             
brew            bazel                                                                          5.2.0                                                                                              
brew            bdw-gc                                                                         8.0.6                                                                                              
brew            bdw-gc                                                                         8.2.2                                                                                              
brew            berkeley-db                                                                    18.1.40_1                                                                                          
brew            boost                                                                          1.80.0                                                                                             
brew            boost-build                                                                    1.79.0                                                                                             
. . .

❯ mac-scan-cli report reset

❯ mac-scan-cli report
No packages discovered
No vulnerabilities found

```

#### Background Watch

```bash
❯ mac-scan-cli status      
Service State:                  Active
Background Watch State:         Stopped

❯ mac-scan-cli background-watch start

❯ mac-scan-cli status                
Service State:                  Active
Background Watch State:         Running

❯ mac-scan-cli report
No packages discovered
No vulnerabilities found

# You can see nothing has changed on my computer yet, so nothing was discovered or found. 
# Let's install an older version of jenkins with ruby gem, immediately stop the scanner 
# so we only get the changes for the period of time we installed jenkins, and then generate the report:

❯ sudo gem install --version 0.6.0 jenkins
Ignoring ffi-1.13.1 because its extensions are not built. Try: gem pristine ffi --version 1.13.1
Fetching jenkins-0.6.0.gem
Successfully installed jenkins-0.6.0
Parsing documentation for jenkins-0.6.0
Installing ri documentation for jenkins-0.6.0
Done installing documentation for jenkins after 0 seconds
1 gem installed

❯ mac-scan-cli background-watch stop

❯ mac-scan-cli report vulnerabilities | head -20
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
```

## REST API

An alternative to the included CLI is using the API directly with `curl`.

### /v1/status

Returns the state of the scanning.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Stopped"},"error":""}
```

### /v1/backgroundwatch/start (POST)

Starts the scanning.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Stopped"},"error":""}
❯ curl -X POST http://localhost:8081/v1/backgroundwatch/start
{"status":"OK","body":{"state":"Running"},"error":""}
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Running"},"error":""}
```

### /v1/backgroundwatch/stop (POST)

Stops the scanning and forces population of packages and vulnerabilities.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Running"},"error":""}
❯ curl -X POST http://localhost:8081/v1/backgroundwatch/stop
{"status":"OK","body":{"state":"Running"},"error":""}
# Be patient as this can take a long time to return depending on the scan's state
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Stopped"},"error":""}
```

### /v1/fullscan (POST)

Stops the scanning and forces population of packages and vulnerabilities.

```bash
❯ curl -X POST http://localhost:8081/v1/fullscan
{"status":"OK","body":{"state":"Creating catalog"},"error":""}
❯ curl http://localhost:8081/v1/status          
{"status":"OK","body":{"state":"Creating catalog"},"error":""}
```

### /v1/report

Generates and outputs to STDOUT a report of packages and vulnerabilities the scan found while running.

```bash
❯ curl -s http://localhost:8081/v1/report | jq | head -50
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
❯ curl -s http://localhost:8081/v1/report | jq '.body.vulnerabilities' | head -50
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

#### /v1/report/packages

Generates and outputs to STDOUT a report of ONLY the packages the scan found while running.

```bash
❯ curl -s http://localhost:8081/v1/report/packages | jq | head -50
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

#### /v1/report/vulnerabilities

Generates and outputs to STDOUT a report of ONLY vulnerabilities the scan found while running.

```bash
❯ curl -s http://localhost:8081/v1/report/vulnerabilities | jq | head -50
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

### /v1/report/reset (POST)

Resets the current catalog of vulnerabilities and packages.

```bash
❯ curl -X POST http://localhost:8081/v1/report/reset
{"status":"OK","body":{"state":"Running"},"error":""}
```

#### ?fromTime=

Reports endpoints allow setting the `fromTime` to isolate packages and vulnerabilities from a specific time.

**The time must be in RFC3339.** On MacOS, you can generate this time using `date -u +%Y-%m-%dT%H:%M:%SZ`.

```bash
❯ curl -s http://localhost:8081/v1/report/vulnerabilities\?fromTime\=2022-09-13T12:47:33Z | jq | head -50
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
