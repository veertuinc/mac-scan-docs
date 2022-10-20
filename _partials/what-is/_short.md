---
---

# About Mac Scan (beta)

It's very common to download various packages and libraries on your build machines as part of CI/CD job execution. If any of these downloaded packages contain security vulnerabilities, it can create opportunity for bad actors to exploit these vulnerabilities and introduce undesirable actions during build and test automation. Some of these actions could be introducing exploits with the app, expose secrets, and allow infiltration of your internal network. Veertu's Mac Scan tool can identify security vulnerabilities in these downloaded libraries and packages during runtime (when the build and test job is running) and flag them, leaving it up to your team to script what actions to take from the results. You can choose to fail the job and address the vulnerabilities detected or mark them as success, but log the vulnerabilities to resolve later.

Scannable languages/packages:

- Ruby Gems
- Python Packages
- Javascript Node/NPM Packages
- Java Packages
- Golang Modules
- Rust Cargo
- Brew Formula
- MacOS Applications
- Cocoapods

---

Mac Scan supports two modes of scanning:

##### Fullscan mode

In full scan mode, the scanner will check applications, libraries, and other third-party packages installed on the macOS file system for security vulnerabilities. Since a Full Scan scans the entire file system, it can take up to a few minutes. Scan report after full scan contains a catalog of all packages and all security vulnerabilities identified in those packages(CVE ).

##### Background Watch

In Background Watch mode, the scan tool only scans, in real-time, everything that’s downloaded on the macOS filesystem. Scan report at any given time will contain a catalog of downloaded packages and all security vulnerabilities identified in those packages (CVE).

Mac Scan can be installed on physical macOS machines (Intel and Apple Silicon are supported), macOS Virtual Machines, and AWS EC2 Mac instances. The general recommendation is after installing the Mac Scan to first execute it in FullScan mode, analyze the discovered security vulnerabilities(CVEs), reset the report, and then switch to Background Watch mode.

In Background Watch mode, the Mac Scan tool continuously scans anything downloaded on the macOS file system. While doing continuous scanning, the tool is built to minimize the consumption of macOS CPU and RAM resources, so there is no impact on other activities/tasks occurring on the machine.

Suggested workflow to use Mac Scan tool to scan for security vulnerabilities during iOS CI

**Step 1** - Install the Mac Scan application package on physical, virtual, or AWS EC2 Mac systems.

**Step 2** - Execute FullScan

**Step 3** - Analyze discovered vulnerabilities

**Step 4** - Change the Mac Scan mode to Background Watch

**Step 5** - Since your CI jobs download various packages, libraries, etc from internal repos and the internet, add steps in the CI jobs to check for mac scan report output and take appropriate actions based on discovered vulnerabilities in downloaded packages, libraries.
