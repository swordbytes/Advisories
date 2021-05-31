# SwordBytes Security Advisories
List of Security advisories released by SwordBytes

---

## CVE-2021-33501 - Overwolf 1-Click Remote Code Execution

**CVE ID:** CVE-2021-33501\
**Vendor:** Overwolf Ltd\
**Class:** CWE-94 - Improper Control of Generation of Code (\'Code
Injection\')\
**Severity:** Critical - 9.6
(CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)\
**Affected version(s):** Overwolf Client 0.169.0.22 (prior versions
might also be affected)\
**Credits:** This vulnerability was discovered and researched by Joel Noguera.\
**Description:** SwordBytes researchers have identified an Unauthenticated Remote Code Execution (RCE) vulnerability in Overwolf’s Client Application by abusing a Reflected Cross-Site Scripting (XSS) issue present in the “overwolfstore://” URL handler. This vulnerability allows remote unauthenticated attackers to execute arbitrary commands on the underlying operating system that hosts Overwolf’s Client Application.


PDF Version: https://github.com/swordbytes/Advisories/blob/master/2021/Advisory_CVE-2021-33501.pdf \
Web Version: https://swordbytes.com/blog/security-advisory-overwolf-1-click-remote-code-execution-cve-2021-33501/
