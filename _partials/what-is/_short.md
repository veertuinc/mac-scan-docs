---
---

# About Runtime Mac Scan (beta)

It's very common to download various packages and libraries on your build machines as part of CI/CD job execution. If any of these downloaded packages contain security vulnerabilities, it can create opportunity for bad actors to exploit these vulnerabilities and introduce undesirable actions during build and test automation. Some of these actions could be introducing exploits with the app, expose secrets, and allow infiltration of your internal network. Veertu's Runtime Mac Scan tool can identify security vulnerabilities in these downloaded libraries and packages during runtime(when the build and test job is running) and flag them, leaving it up to your team to script what actions to take from the results. You can choose to fail the job and address the vulnerabilities detected or mark them as success, but log the vulnerabilities to resolve later.

The Runtime Mac Scan tool works in complete non-intrusive mode inside the build machine with no impact on build performance.

After installing the Runtime Mac Scan tool inside of your bare metal or virtual machine, modify your build or test job script to add the "Start scan", "Stop scan" and "Report scan" steps. Then, depending on the results of "Report scan", if security vulnerabilities are identified in the downloaded packages, update the job scripts to fail or pass and take any actions to log the results of scan.
