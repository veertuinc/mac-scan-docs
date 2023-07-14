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
version: 0.3.0
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
  mac-scan-0.5.0
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

### Scan Modes

#### Full Scan

```bash
❯ mac-scan-cli
This tool provides an interface to communicate with the mac-scand API

Usage:
  mac-scan-cli [flags]
  mac-scan-cli [command]

Available Commands:
  completion     Generate the autocompletion script for the specified shell
  full-scan      Start full scan
  help           Help about any command
  license        License show/activate
  real-time-scan Start real-time scan in background
  report         Report scanning result
  status         Get status
  version        Print the version number of mac-scan

Flags:
  -h, --help       help for mac-scan-cli
  -p, --port int   default port (default 8081)

Use "mac-scan-cli [command] --help" for more information about a command.

❯ mac-scan-cli report
No packages discovered
No vulnerabilities found

❯ mac-scan-cli full-scan --help
Starts full scan of the disk to catalog all packages and vulnerabilities

Usage:
  mac-scan-cli full-scan [flags]

Flags:
  -h, --help             help for full-scan
  -w, --no-wait          Start full scan in the background
  -d, --path string      Path to scan
  -b, --real-time-scan   Start real-time scan after full scan is complete

Global Flags:
  -p, --port int   default port (default 8081)

❯ mac-scan-cli full-scan

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

#### Real-Time Scan

```bash
❯ mac-scan-cli status      
Service State: 	Active
Scan State: 	  Idle

❯ mac-scan-cli real-time-scan start --help
Tells runtime scanner to start real-time package inspect

Usage:
  mac-scan-cli real-time-scan start [flags]

Flags:
  -h, --help          help for start
  -d, --path string   Path to scan

Global Flags:
  -p, --port int   default port (default 8081)

❯ mac-scan-cli real-time-scan start

❯ mac-scan-cli status                
Service State:  Active
Scan State:     Real-Time

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

❯ mac-scan-cli real-time-scan stop

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

#### Filtering and Sorting

```bash
❯ mac-scan-cli report vulnerabilities --help
Display detected vulnerabilities from the beginning of the last start command or user provided date

Usage:
  mac-scan-cli report vulnerabilities [flags]

Flags:
  -h, --help   help for vulnerabilities

Global Flags:
  -c, --display-columns string   display columns for table format, columns=[Type - 't' Name - 'n' Version - 'v' Vulnerability - 'V' Score - 's' Severity - 'S' Location - 'l']
  -m, --min-score float32        filter vulnerabilities by score
  -f, --report-format string     report output format, formats=[json table] (default "table")
  -s, --sort string              sort results for table format, options=[{score,s} {name,n} {type,t}]
  -t, --timestamp string         report packages newer than specified time (RFC3339 format)
```

```bash
❯ mac-scan-cli report packages --help       
Display detected packages from the beginning of the last start command or user provided date

Usage:
  mac-scan-cli report packages [flags]

Flags:
  -h, --help   help for packages

Global Flags:
  -c, --display-columns string   display columns for table format, columns=[Type - 't' Name - 'n' Version - 'v' Vulnerability - 'V' Score - 's' Severity - 'S' Location - 'l']
  -m, --min-score float32        filter vulnerabilities by score
  -f, --report-format string     report output format, formats=[json table] (default "table")
  -s, --sort string              sort results for table format, options=[{score,s} {name,n} {type,t}]
  -t, --timestamp string         report packages newer than specified time (RFC3339 format)
```

There are several ways to filter results:

1. **`--min-score`** to specify minimal score:

  ```bash
  ❯ mac-scan-cli report vulnerabilities --min-score 8.3
  TYPE  NAME                VERSION  VULNERABILITY   SCORE  SEVERITY 
  npm   chainsaw            0.1.0    CVE-2020-9493   9.8    critical  
  npm   chainsaw            0.1.0    CVE-2022-23307  9.0    critical  
  npm   connect             3.7.0    CVE-2016-0948   8.8    high      
  npm   connect             3.7.0    CVE-2016-0949   10.0   critical  
  npm   connect             3.7.0    CVE-2017-11291  10.0   critical  
  npm   connect             3.7.0    CVE-2018-12804  9.8    critical  
  npm   connect             3.7.0    CVE-2018-12805  9.8    critical  
  npm   connect             3.7.0    CVE-2018-4923   9.1    critical  
  npm   connect             3.7.0    CVE-2021-40719  9.8    critical  
  npm   json-schema         0.2.3    CVE-2021-3918   9.8    critical  
  npm   minimist            1.2.5    CVE-2021-44906  9.8    critical  
  npm   shell-quote         1.7.2    CVE-2021-42740  9.8    critical  
  npm   socket.io-parser    3.4.1    CVE-2022-2421   9.8    critical  
  npm   tar                 6.1.0    CVE-2021-37701  8.6    high      
  npm   tar                 6.1.0    CVE-2021-37712  8.6    high      
  npm   tar                 6.1.0    CVE-2021-37713  8.6    high      
  npm   through             2.3.8    CVE-2021-29940  9.8    critical  
  npm   xmlhttprequest-ssl  1.5.5    CVE-2021-31597  9.4    critical  
  ```

2. **`--sort [sntv]`** to sort table results only (sort by score, name, package type, version). `s` is a short for score, `n` - name, `t` - package type, and `v` - version.

  ```bash
  ❯ mac-scan-cli report vulnerabilities --min-score 8.3 --sort s
  TYPE  NAME                VERSION  VULNERABILITY   SCORE  SEVERITY 
  npm   connect             3.7.0    CVE-2016-0949   10.0   critical  
  npm   connect             3.7.0    CVE-2017-11291  10.0   critical  
  npm   chainsaw            0.1.0    CVE-2020-9493   9.8    critical  
  npm   connect             3.7.0    CVE-2018-12804  9.8    critical  
  npm   connect             3.7.0    CVE-2018-12805  9.8    critical  
  npm   connect             3.7.0    CVE-2021-40719  9.8    critical  
  npm   json-schema         0.2.3    CVE-2021-3918   9.8    critical  
  npm   minimist            1.2.5    CVE-2021-44906  9.8    critical  
  npm   shell-quote         1.7.2    CVE-2021-42740  9.8    critical  
  npm   socket.io-parser    3.4.1    CVE-2022-2421   9.8    critical  
  npm   through             2.3.8    CVE-2021-29940  9.8    critical  
  npm   xmlhttprequest-ssl  1.5.5    CVE-2021-31597  9.4    critical  
  npm   connect             3.7.0    CVE-2018-4923   9.1    critical  
  npm   chainsaw            0.1.0    CVE-2022-23307  9.0    critical  
  npm   connect             3.7.0    CVE-2016-0948   8.8    high      
  npm   tar                 6.1.0    CVE-2021-37701  8.6    high      
  npm   tar                 6.1.0    CVE-2021-37712  8.6    high      
  npm   tar                 6.1.0    CVE-2021-37713  8.6    high 
  ```

3. **`--display-columns [tnsSvVl]`** to show specific table columns. `t` is for package type, `n` - name, `s` - score, `S` - severity, `v` - version, `V` - vulnerability id, `l` - location/path to vulnerability

  ```bash
  ❯ mac-scan-cli report vulnerabilities --display-columns nSvVl --sort s --min-score 8.5 | head
  NAME                  SEVERITY  VERSION            VULNERABILITY     LOCATION                                                                           
  activerecord          critical  3.0.1              CVE-2022-32224    /Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/fixtures/projects/rails-3/Gemfile.lock  
  bundler               critical  1.17.2             CVE-2020-36327    /Library/Ruby/Gems/2.6.0/specifications/default/bundler-1.17.2.gemspec              
  bundler               critical  1.17.2             CVE-2021-43809    /Library/Ruby/Gems/2.6.0/specifications/default/bundler-1.17.2.gemspec              
  cocoapods-downloader  critical  1.2.2              CVE-2022-21223    /Library/Ruby/Gems/2.6.0/gems/cocoapods-trunk-1.5.0/Gemfile.lock                    
  cocoapods-downloader  critical  1.2.2              CVE-2022-24440    /Library/Ruby/Gems/2.6.0/gems/cocoapods-trunk-1.5.0/Gemfile.lock                    
  cocoapods-downloader  critical  1.3.0              CVE-2022-21223    /Library/Ruby/Gems/2.6.0/gems/cocoapods-try-1.2.0/Gemfile.lock                      
  cocoapods-downloader  critical  1.3.0              CVE-2022-24440    /Library/Ruby/Gems/2.6.0/gems/cocoapods-try-1.2.0/Gemfile.lock                      
  git                   critical  1.1.4              CVE-2014-9390     /Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/fixtures/jenkins/git.hpi                
  git                   critical  1.1.4              CVE-2015-7082     /Library/Ruby/Gems/2.6.0/gems/jenkins-0.6.0/fixtures/jenkins/git.hpi     
  ```
  
## REST API

An alternative to the included CLI is using the API directly with `curl`.

### /v1/status

Returns the state of the scanning.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Idle"},"error":""}
```

### /v1/real-time-scan/start (POST)

Starts the scanning.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Idle"},"error":""}
❯ curl -X POST http://localhost:8081/v1/real-time-scan/start
{"status":"OK","body":{"state":"Real-Time"},"error":""}
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Real-Time"},"error":""}
```

#### ?path=

Allows you to target scanning under a specific directory

```bash
❯ curl -s -X POST http://localhost:8081/v1/real-time-scan/start\?path\=/Library/Ruby/Gems
{"status":"OK","body":{"state":"Running Full"},"error":""}
```

### /v1/real-time-scan/stop (POST)

Stops the scanning and forces population of packages and vulnerabilities.

```bash
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Real-Time"},"error":""}
❯ curl -X POST http://localhost:8081/v1/real-time-scan/stop
{"status":"OK","body":{"state":"Real-Time"},"error":""}
# Be patient as this can take a long time to return depending on the scan's state
❯ curl http://localhost:8081/v1/status
{"status":"OK","body":{"state":"Idle"},"error":""}
```

### /v1/full-scan (POST)

Stops the scanning and forces population of packages and vulnerabilities.

```bash
❯ curl -X POST http://localhost:8081/v1/full-scan
{"status":"OK","body":{"state":"Running Full"},"error":""}
❯ curl http://localhost:8081/v1/status          
{"status":"OK","body":{"state":"Running Full"},"error":""}
```

#### ?path=

Allows you to target scanning under a specific directory

```bash
❯ curl -s -X POST http://localhost:8081/v1/full-scan\?path\=/Library/Ruby/Gems/2.6.0
{"status":"OK","body":{"state":"Running Full"},"error":""}
❯ mac-scan-cli report vulnerabilities | head                                       
TYPE          NAME                  VERSION            VULNERABILITY     SCORE  SEVERITY 
gem           actionpack            3.0.1              CVE-2022-27777    6.1    medium    
gem           activerecord          3.0.1              CVE-2022-32224    9.8    critical  
gem           activerecord          3.0.1              CVE-2022-44566    7.5    high      
gem           addressable           2.3.7              CVE-2021-32740    7.5    high      
gem           addressable           2.5.1              CVE-2021-32740    7.5    high      
gem           addressable           2.7.0              CVE-2021-32740    7.5    high      
gem           bundler               1.17.2             CVE-2019-3881     7.8    high      
gem           bundler               1.17.2             CVE-2020-36327    9.3    critical  
gem           bundler               1.17.2             CVE-2021-43809    9.3    critical  
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

#### ?min_score=

Reports endpoints allow setting the `min_score` to isolate packages and vulnerabilities with certain scores. Can be an integer or decimal.

```bash
❯ curl -s -X POST "http://localhost:8081/v1/report/vulnerabilities?min_score=8.2" | jq '.body[] | [.Vulnerability.Score,.Package.Name,.Package.Locations[0].path] | join(",")'
"9.8,minimist,/Users/user1/project/themes/docsy/userguide/package-lock.json"
"9.4,xmlhttprequest-ssl,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,chainsaw,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9,chainsaw,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,json-schema,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,json-schema,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,socket.io-parser,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"8.8,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"10,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"10,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.1,connect,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,shell-quote,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,shell-quote,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,minimist,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"8.6,tar,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"8.6,tar,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"8.6,tar,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,through,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,through,/Users/user1/project/themes/docsy/assets/vendor/bootstrap/package-lock.json"
"9.8,through,/Users/user1/project/node_modules/through/package.json"
"9.8,through,/Users/user1/project/node_modules/through/package.json"
"9.8,through,/Users/user1/project/package-lock.json"
"9.8,through,/Users/user1/project/package-lock.json"
```


### /v1/report/reset (POST)

Resets the current catalog of vulnerabilities and packages.

```bash
❯ curl -X POST http://localhost:8081/v1/report/reset
{"status":"OK","body":{"state":"Real-Time"},"error":""}
```
