/* ============================================================
   SOC SENTINEL — script.js
   Security Operations Center Simulator
   All data is FICTIONAL and for EDUCATIONAL USE ONLY
   ============================================================ */

"use strict";

// ─────────────────────────────────────────────
// DATA LAYER
// ─────────────────────────────────────────────

const ALERTS = [
  {
    id: "ALT-001", severity: "Critical", type: "Ransomware",
    title: "Ransomware Deployment Detected on Finance Server",
    source: "192.168.10.45", dest: "192.168.10.0/24",
    time: "2024-06-14 08:12:33", status: "Open",
    analyst: "Unassigned",
    description: "EDR detected an attempt to encrypt files using a pattern consistent with LockBit 3.0 ransomware. The process 'svchost32.exe' was spawned by a macro-enabled Word document attachment.",
    indicators: ["svchost32.exe (non-standard path)", "Registry key: HKCU\\Software\\LockBit", "Mass file extension change to .lckd", "C2 callback to 198.51.100.44:443"],
    recommendations: [
      "Immediately isolate host 192.168.10.45 from the network.",
      "Suspend user account that opened the malicious document.",
      "Snapshot the affected disk for forensic analysis.",
      "Check backup integrity — do NOT pay ransom.",
      "Scan all adjacent hosts for lateral movement.",
      "Notify incident response team and legal/compliance.",
    ],
    mitre: "T1486 – Data Encrypted for Impact",
  },
  {
    id: "ALT-002", severity: "Critical", type: "Phishing",
    title: "Spear Phishing Campaign Targeting Executive Accounts",
    source: "External (spoofed: ceo@corp-acme.net)", dest: "c-suite@victim.org",
    time: "2024-06-14 09:02:15", status: "Investigating",
    analyst: "J. Torres",
    description: "Email gateway flagged 47 spear-phishing emails mimicking the CEO domain. Emails contain a OneDrive link redirecting to a credential harvesting page hosted on a lookalike domain (c0rp-acme.net).",
    indicators: ["Sender domain: c0rp-acme.net (lookalike)", "Subject: URGENT – Wire Transfer Authorization", "Link: hxxps://c0rp-acme.net/auth/sso", "3 employees reported clicking"],
    recommendations: [
      "Block domain c0rp-acme.net at DNS and email gateway.",
      "Force password reset for all recipients immediately.",
      "Enable conditional access for executive accounts.",
      "Submit phishing URL to threat intelligence feeds.",
      "Run awareness training with impacted employees.",
    ],
    mitre: "T1566.001 – Spearphishing Attachment",
  },
  {
    id: "ALT-003", severity: "High", type: "Suspicious Login",
    title: "Impossible Travel Login from VPN Bypass",
    source: "185.220.101.33 (Tor Exit Node)", dest: "vpn-auth.corp",
    time: "2024-06-14 10:45:07", status: "Open",
    analyst: "Unassigned",
    description: "User 'msmith' authenticated from New York at 09:30 and from a Tor exit node in Romania 75 minutes later — physically impossible travel. Account has admin privileges on 3 servers.",
    indicators: ["Login from known Tor exit node", "Geolocation delta: 9,000 km in 75 minutes", "Account: msmith (admin)", "No MFA challenge triggered"],
    recommendations: [
      "Immediately suspend msmith account pending investigation.",
      "Revoke all active sessions for this account.",
      "Review all actions taken in the 75-minute window.",
      "Enforce MFA for all admin accounts.",
      "Add Tor exit nodes to block list at perimeter.",
    ],
    mitre: "T1078 – Valid Accounts",
  },
  {
    id: "ALT-004", severity: "High", type: "Malware",
    title: "Cobalt Strike Beacon Detected on Workstation",
    source: "192.168.1.88", dest: "45.33.32.156:443",
    time: "2024-06-14 11:30:55", status: "Investigating",
    analyst: "R. Patel",
    description: "Network sensor identified periodic HTTPS beaconing consistent with Cobalt Strike stager. Beacon interval: 60s ±10%, using malleable C2 profile mimicking Google Analytics traffic.",
    indicators: ["Periodic 60s HTTPS beacon to 45.33.32.156", "User-Agent: GoogleAnalytics/2.4 (non-standard)", "Loaded reflective DLL in memory", "PowerShell spawned from Word.exe"],
    recommendations: [
      "Isolate workstation 192.168.1.88 immediately.",
      "Memory-dump the process for forensic analysis.",
      "Block 45.33.32.156 at firewall and proxy.",
      "Hunt for similar beaconing on all endpoints.",
      "Rotate credentials used on infected machine.",
    ],
    mitre: "T1071.001 – C2 over HTTPS",
  },
  {
    id: "ALT-005", severity: "High", type: "Network Anomaly",
    title: "Unusual Outbound Data Exfiltration over DNS",
    source: "192.168.5.12", dest: "exfil.attacker-domain.io",
    time: "2024-06-14 12:10:44", status: "Open",
    analyst: "Unassigned",
    description: "DNS monitoring detected unusually long FQDN queries (avg 200 chars) to a recently registered domain. Pattern is consistent with DNS tunneling used for data exfiltration, transferring ~4.2 GB over 6 hours.",
    indicators: ["DNS queries avg 200 chars (normal < 50)", "Domain registered 3 days ago", "4.2 GB transferred via DNS", "TXT record responses contain base64 data"],
    recommendations: [
      "Block domain at recursive DNS resolver.",
      "Capture full PCAP for forensic decode.",
      "Identify what data was encoded in DNS payloads.",
      "Implement DNS query length limits at resolver.",
      "Audit permissions of process making DNS calls.",
    ],
    mitre: "T1048.003 – Exfiltration over DNS",
  },
  {
    id: "ALT-006", severity: "Medium", type: "Brute Force",
    title: "SSH Brute Force Attack on Jump Server",
    source: "203.0.113.99", dest: "10.0.0.5:22",
    time: "2024-06-14 13:05:20", status: "Open",
    analyst: "Unassigned",
    description: "IDS detected 2,847 failed SSH authentication attempts from a single IP in 12 minutes against the jump server. Account lockout prevented successful access. Attack pattern matches hydra tool signature.",
    indicators: ["2,847 failed SSH attempts in 12 min", "Source: 203.0.113.99 (blacklisted IP)", "Hydra tool HTTP header signature", "Targeting root and admin accounts"],
    recommendations: [
      "Block source IP at perimeter firewall.",
      "Enable fail2ban or equivalent SSH brute-force protection.",
      "Disable root SSH login on jump server.",
      "Implement certificate-based SSH authentication.",
      "Review SSH access logs for any success.",
    ],
    mitre: "T1110 – Brute Force",
  },
  {
    id: "ALT-007", severity: "Medium", type: "Insider Threat",
    title: "Employee Downloading Bulk Sensitive Files at 2 AM",
    source: "192.168.3.77", dest: "SharePoint Internal",
    time: "2024-06-14 02:18:40", status: "Investigating",
    analyst: "K. Nakamura",
    description: "DLP alert triggered when user 'bjohnson' downloaded 1,240 confidential documents from SharePoint at 2:18 AM on a weekday, 3 days before their notified resignation date.",
    indicators: ["1,240 downloads in 24 minutes", "Outside business hours (02:18 AM)", "User bjohnson resigned 3 days ago", "Files tagged CONFIDENTIAL and PII"],
    recommendations: [
      "Preserve all logs and prevent evidence tampering.",
      "Suspend SharePoint access pending HR/legal review.",
      "Audit USB and cloud upload activity for this user.",
      "Initiate insider threat investigation procedure.",
      "Coordinate with Legal and HR before any action.",
    ],
    mitre: "T1530 – Data from Cloud Storage",
  },
  {
    id: "ALT-008", severity: "Medium", type: "Vulnerability",
    title: "Unpatched Log4Shell Vulnerability in Production API",
    source: "Internal Scan", dest: "api.internal:8443",
    time: "2024-06-14 07:30:00", status: "Open",
    analyst: "Unassigned",
    description: "Automated vulnerability scanner detected Log4j 2.14.1 (CVE-2021-44228) in the production API server. JNDI lookup in HTTP User-Agent header confirmed exploitable. CVSS: 10.0 Critical.",
    indicators: ["Log4j version 2.14.1 detected", "CVE-2021-44228 (CVSS 10.0)", "Public exploit available", "Internet-facing endpoint"],
    recommendations: [
      "Patch Log4j to 2.17.1 or later immediately.",
      "Deploy WAF rule to block JNDI lookup strings.",
      "Review access logs for exploitation attempts.",
      "Conduct post-patch regression testing.",
    ],
    mitre: "T1190 – Exploit Public-Facing Application",
  },
  {
    id: "ALT-009", severity: "Low", type: "Policy Violation",
    title: "USB Storage Device Connected on Air-Gapped Network",
    source: "WORKSTATION-042", dest: "Local",
    time: "2024-06-14 14:55:11", status: "Closed",
    analyst: "J. Torres",
    description: "Endpoint management detected a USB mass storage device connected to a workstation on the classified network segment, which prohibits removable media per security policy.",
    indicators: ["USB device: Kingston 16GB", "Device serial: E9F3B1...", "Classified network segment", "No authorized exception on file"],
    recommendations: [
      "Disable USB ports via Group Policy or endpoint controls.",
      "Audit the USB device contents.",
      "Issue formal policy violation notice to user.",
      "Review USB whitelist/blacklist policy.",
    ],
    mitre: "T1091 – Replication via Removable Media",
  },
  {
    id: "ALT-010", severity: "Low", type: "Reconnaissance",
    title: "External Port Scan Detected from Shodan IP",
    source: "198.20.69.74 (Shodan)", dest: "203.0.113.10",
    time: "2024-06-14 16:20:00", status: "Resolved",
    analyst: "Auto",
    description: "Perimeter IDS detected a systematic TCP port scan of 65,535 ports from a known Shodan crawler IP. No exploits followed. Low priority but logged for trend analysis.",
    indicators: ["65,535 port probe in 8 minutes", "Source: Shodan crawler (known)", "No successful connections", "Perimeter firewall blocked all"],
    recommendations: [
      "No immediate action required — Shodan crawls are automated.",
      "Ensure no unexpected ports are exposed to internet.",
      "Review firewall rules to confirm DMZ exposure is minimal.",
    ],
    mitre: "T1595 – Active Scanning",
  },
  {
    id: "ALT-011", severity: "Critical", type: "Account Takeover",
    title: "Admin Account Credentials Found in Dark Web Dump",
    source: "Threat Intelligence Feed", dest: "admin@corp.internal",
    time: "2024-06-14 06:00:00", status: "Resolved",
    analyst: "R. Patel",
    description: "Threat intelligence platform flagged admin@corp.internal credentials in a dark web credential dump linked to a stealer malware campaign. Password hash and cleartext were both present.",
    indicators: ["Cleartext password exposed", "Found in 'SteaLog_062024' dataset", "Account has domain admin rights", "Password not rotated in 11 months"],
    recommendations: [
      "Force immediate password reset.",
      "Audit all recent logins for this account.",
      "Enable MFA and privileged access management.",
      "Check if credentials were reused on other systems.",
    ],
    mitre: "T1078.002 – Domain Accounts",
  },
  {
    id: "ALT-012", severity: "High", type: "Lateral Movement",
    title: "Pass-the-Hash Attack Detected Across Domain",
    source: "192.168.10.45", dest: "192.168.10.0/24",
    time: "2024-06-14 08:45:00", status: "Investigating",
    analyst: "K. Nakamura",
    description: "SIEM correlation rule triggered: same NTLM hash used to authenticate against 14 different servers within 5 minutes from a single compromised workstation, indicating a Pass-the-Hash lateral movement attack.",
    indicators: ["Same NTLM hash on 14 servers in 5 min", "Source: WKSTN-045", "Account: svc_backup (service account)", "Mimikatz artifact in memory"],
    recommendations: [
      "Isolate WKSTN-045 immediately.",
      "Reset svc_backup credentials across all systems.",
      "Enable Protected Users Security Group in AD.",
      "Disable NTLM authentication where possible.",
      "Run full domain password audit.",
    ],
    mitre: "T1550.002 – Pass the Hash",
  },
];

const INCIDENTS = [
  {
    id: "INC-2024-0021", title: "Ransomware Outbreak – Finance Segment",
    severity: "Critical", status: "Investigating",
    assignee: "Incident Response Team",
    created: "2024-06-14 08:15", updated: "2024-06-14 11:30",
    affectedSystems: "5 workstations, 1 file server",
    relatedAlerts: ["ALT-001", "ALT-012"],
    description: "Ransomware deployment detected across finance network segment. Initial vector is a macro-enabled email attachment. Containment in progress.",
  },
  {
    id: "INC-2024-0020", title: "CEO Email Fraud Spear Phishing Campaign",
    severity: "High", status: "Open",
    assignee: "J. Torres",
    created: "2024-06-14 09:10", updated: "2024-06-14 09:45",
    affectedSystems: "Email platform, 47 mailboxes",
    relatedAlerts: ["ALT-002"],
    description: "Coordinated spear-phishing campaign targeting executive accounts using CEO impersonation. 3 credential compromises confirmed.",
  },
  {
    id: "INC-2024-0019", title: "Cobalt Strike C2 Beacon – Engineering Segment",
    severity: "High", status: "Investigating",
    assignee: "R. Patel",
    created: "2024-06-14 11:35", updated: "2024-06-14 13:00",
    affectedSystems: "2 engineering workstations",
    relatedAlerts: ["ALT-004"],
    description: "Active Cobalt Strike beacon detected. Post-exploitation activity ongoing. Threat actor has gained foothold in engineering network.",
  },
  {
    id: "INC-2024-0018", title: "Insider Data Exfiltration – Pre-Resignation",
    severity: "Medium", status: "Investigating",
    assignee: "K. Nakamura",
    created: "2024-06-14 03:00", updated: "2024-06-14 10:00",
    affectedSystems: "SharePoint, User Endpoint",
    relatedAlerts: ["ALT-007"],
    description: "Potential insider threat — departing employee bulk-downloaded sensitive documents outside business hours. Legal and HR involved.",
  },
  {
    id: "INC-2024-0017", title: "Dark Web Credential Exposure – Admin Account",
    severity: "Critical", status: "Resolved",
    assignee: "R. Patel",
    created: "2024-06-14 06:05", updated: "2024-06-14 07:20",
    affectedSystems: "Active Directory",
    relatedAlerts: ["ALT-011"],
    description: "Admin credentials found in dark web dump. Immediate password reset completed. No unauthorized access confirmed during 6-hour investigation window.",
  },
  {
    id: "INC-2024-0016", title: "DNS Tunneling – Data Exfiltration via DNS",
    severity: "High", status: "Open",
    assignee: "Unassigned",
    created: "2024-06-14 12:15", updated: "2024-06-14 12:15",
    affectedSystems: "Workstation 192.168.5.12",
    relatedAlerts: ["ALT-005"],
    description: "Approximately 4.2 GB of data exfiltrated via DNS tunneling. Forensic analysis of DNS payloads in progress to determine data classification.",
  },
];

const MISSIONS = [
  {
    id: "MSN-01",
    tag: "Phishing Response",
    title: "The Executive Email Trap",
    desc: "A CFO reports receiving a suspicious email. Assess and respond.",
    scenario: `Your SIEM alerts you that 3 executives have clicked a link in an email appearing to come from the CEO. The link redirected them to an external site before your proxy blocked it. The CFO's Outlook is now behaving strangely — auto-forwarding sent items to an unknown address. You have 10 minutes before close of business.\n\nThe email header analysis shows: From: ceo@c0rp-acme.net (not the real domain), SPF: FAIL, DKIM: FAIL.`,
    question: "What is your FIRST priority action?",
    options: [
      { text: "A. Reply to the phishing email to gather more information about the attacker.", correct: false, feedback: "❌ Never engage with a phishing sender. You could confirm the email is active, expose internal info, or trigger further attacks. Engaging attackers is not a valid SOC response." },
      { text: "B. Reset the CFO's password and revoke active sessions, then block the sender domain.", correct: true, feedback: "✅ Correct! Immediate credential reset + session revocation stops active account takeover. Blocking the domain prevents further clicks. This is the textbook first response to a confirmed credential phishing click." },
      { text: "C. Send a company-wide warning email explaining the phishing attack in detail.", correct: false, feedback: "❌ While awareness is important, broadcasting attack details too early can cause panic, alert the insider if one exists, and leak investigation information. First contain the damage." },
      { text: "D. Quarantine the email from all inboxes but take no account action yet.", correct: false, feedback: "❌ Email quarantine is good but not sufficient when accounts may already be compromised. The auto-forward rule on the CFO's account indicates active account takeover — credential revocation is urgent." },
    ],
    points: 100,
  },
  {
    id: "MSN-02",
    tag: "Ransomware Containment",
    title: "Ransomware on the File Server",
    desc: "Files are being encrypted on a shared drive. Act now.",
    scenario: `At 08:12 an EDR alert fires: the process 'svchost32.exe' running from C:\\Users\\Public\\ is performing mass file renames on the shared finance drive (\\\\FS01\\Finance). Files are changing to the .lckd extension. The affected server hosts Q2 financial data for 200 users.\n\nYou can see the process started from a macro in an email attachment opened by finance user 'klee' 4 minutes ago. Backups ran last night at 22:00 and are on a separate network share.`,
    question: "Which containment sequence is correct?",
    options: [
      { text: "A. Delete the encrypted files immediately to stop the spread.", correct: false, feedback: "❌ Never delete encrypted files during an active ransomware incident. They may be partially encrypted and recoverable. Deletion destroys forensic evidence and removes any chance of recovery without backups." },
      { text: "B. Isolate the affected server from the network, suspend klee's account, and verify backup integrity.", correct: true, feedback: "✅ Correct! Network isolation stops encryption spread. Suspending the account stops re-infection. Verifying backups before anything else ensures you have a clean recovery path. This is the standard ransomware playbook sequence." },
      { text: "C. Reboot the file server to kill the ransomware process.", correct: false, feedback: "❌ Rebooting may trigger ransomware to complete encryption, delete shadow copies, or execute additional payloads on startup. Isolation is always preferred over reboot during active ransomware." },
      { text: "D. Pay the ransom demand immediately to restore file access for the business.", correct: false, feedback: "❌ Paying ransom is never recommended as the first response. It funds criminal operations, does not guarantee decryption, and may violate compliance regulations. Always exhaust recovery options first." },
    ],
    points: 150,
  },
  {
    id: "MSN-03",
    tag: "Threat Hunting",
    title: "The Sleeping Intruder",
    desc: "Unusual C2 beaconing detected — investigate the pattern.",
    scenario: `Your threat hunting platform flags a workstation (WKSTN-114) making periodic HTTPS requests every 60 seconds to 45.33.32.156 — an IP flagged in multiple threat intelligence feeds as a Cobalt Strike C2 server. The workstation belongs to a developer. Process tree shows: winword.exe → powershell.exe → rundll32.exe. The activity started 3 days ago.`,
    question: "What does the process tree indicate, and what should you do next?",
    options: [
      { text: "A. It's normal developer activity — PowerShell is commonly used by developers.", correct: false, feedback: "❌ While developers use PowerShell, a process tree of Word → PowerShell → rundll32 is a textbook malicious macro execution chain. Normal development work does not involve Word spawning PowerShell. This pattern warrants immediate investigation." },
      { text: "B. Perform a live memory acquisition of WKSTN-114, then isolate it from the network.", correct: true, feedback: "✅ Correct! Memory acquisition before isolation preserves volatile artifacts (Cobalt Strike typically runs in-memory and disappears on isolation). After capturing memory, network isolation stops active C2 communication. This is best-practice incident response for malware investigations." },
      { text: "C. Block the C2 IP at the firewall only, and monitor to see if another IP is used.", correct: false, feedback: "❌ Blocking the C2 IP alone does not remediate the infected host. Cobalt Strike will simply switch to a backup C2 domain. The compromised endpoint must be isolated and investigated to prevent further damage." },
      { text: "D. Ask the developer to uninstall Microsoft Word and restart their computer.", correct: false, feedback: "❌ User self-remediation of a Cobalt Strike infection is inadequate. The implant runs in memory and survives app uninstallation. Restarting may lose volatile evidence. Professional forensic response is required." },
    ],
    points: 125,
  },
  {
    id: "MSN-04",
    tag: "Insider Threat",
    title: "The Midnight Downloader",
    desc: "A resigning employee is downloading files at 2 AM.",
    scenario: `DLP alerts fire at 02:18 AM: user bjohnson has downloaded 1,240 documents (4.8 GB) from SharePoint in 24 minutes. The files are tagged CONFIDENTIAL and include customer PII. HR notified SOC last week that bjohnson's last day is in 3 days. Security policy requires DLP alerts be investigated before any user-facing action.\n\nYou know bjohnson may have legitimate project work. However, the timing and volume are anomalous.`,
    question: "What is the correct SOC response before taking user-facing action?",
    options: [
      { text: "A. Immediately disable bjohnson's account and delete the downloaded files.", correct: false, feedback: "❌ Account suspension without HR/Legal approval can expose the company to legal liability, especially if the download was legitimate. Deleting files may constitute destruction of evidence. SOC must escalate to the chain of custody process first." },
      { text: "B. Preserve and collect all evidence logs, escalate to HR and Legal, then await guidance before acting.", correct: true, feedback: "✅ Correct! Insider threat cases require legal guidance before user-facing action. Preserving evidence (logs, download manifests, timestamps) in a legally admissible format is essential. HR and Legal must be looped in before account suspension to ensure compliance with employment law." },
      { text: "C. Contact bjohnson directly to ask why they were downloading files at 2 AM.", correct: false, feedback: "❌ Contacting the suspect directly tips them off, giving them time to cover tracks, copy more data, or destroy evidence. Insider threat investigations must be handled covertly until Legal/HR authorize disclosure." },
      { text: "D. Monitor the situation for another 24 hours to gather more data.", correct: false, feedback: "❌ Waiting when exfiltration may be ongoing risks more data loss. The correct response is to immediately preserve and escalate — not to ignore and monitor. Time is critical in data loss prevention scenarios." },
    ],
    points: 100,
  },
  {
    id: "MSN-05",
    tag: "Vulnerability Response",
    title: "Log4Shell in Production",
    desc: "CVE-2021-44228 confirmed on an internet-facing service.",
    scenario: `Vulnerability scanner output confirms Log4j 2.14.1 (CVE-2021-44228, CVSS 10.0) running in your production API gateway — internet-facing on port 443. A working public exploit exists. Your change management process normally requires a 2-week review for production patches, but your CISO has granted emergency authority for critical CVEs.\n\nThe API processes 50,000 requests/hour. Your security team has a WAF available.`,
    question: "What is the recommended emergency response order?",
    options: [
      { text: "A. Deploy a WAF rule to block JNDI lookup strings immediately, then schedule a patch during next change window.", correct: false, feedback: "❌ Deploying a WAF rule is a good interim mitigation, but scheduling a patch for 'next change window' is not acceptable for a CVSS 10.0 vulnerability with a public exploit. Emergency patching under CISO authority should proceed as fast as possible." },
      { text: "B. Take the API offline until patched — availability is less important than security.", correct: false, feedback: "❌ While security is priority, taking a 50K req/hr API offline without a maintenance window plan or business impact assessment is not appropriate. WAF mitigation allows continued operation while patching is prepared, which is a balanced response." },
      { text: "C. Deploy WAF JNDI blocking immediately, fast-track emergency patch with CISO authority, review logs for exploitation attempts.", correct: true, feedback: "✅ Correct! WAF rule provides immediate risk reduction. Emergency patch process (authorized by CISO) addresses root cause. Log review confirms whether exploitation already occurred. This layered response (mitigate → patch → investigate) is best practice for critical CVEs." },
      { text: "D. Notify the vendor of the vulnerability and wait for their official guidance.", correct: false, feedback: "❌ Log4Shell is a publicly known and widely published vulnerability (CVE-2021-44228). The vendor guidance is already available. Waiting for vendor guidance while an internet-exposed CVSS 10.0 vulnerability is unpatched is not an acceptable SOC response." },
    ],
    points: 125,
  },
];

const PLAYBOOKS = [
  {
    id: "PB-01", icon: "🎣", title: "Phishing Incident Response",
    desc: "End-to-end process for handling phishing emails and credential compromise.",
    tag: "critical",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor email gateway for SPF/DKIM/DMARC failures",
          "Correlate reported phishing emails from users",
          "Check proxy and DNS logs for suspicious outbound calls",
          "Review authentication logs for anomalous login patterns",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Analyze email headers for spoofing indicators",
          "Decode and sandbox any links or attachments",
          "Identify all recipients of the campaign",
          "Determine if any credentials were harvested",
          "Check if linked domains are newly registered lookalikes",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "Block sender domain at email gateway and DNS",
          "Force password reset for all users who clicked",
          "Revoke active sessions for compromised accounts",
          "Enable conditional access and MFA challenges",
          "Quarantine similar emails from all inboxes",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Monitor for re-attempts from new domains",
          "Restore account functionality after credential reset",
          "Validate no mail rules were created by attacker",
          "Confirm clean bill of health from all impacted users",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Enable DMARC reject policy on your domain",
          "Deploy anti-phishing simulation training",
          "Configure email banners for external senders",
          "Review and tighten email gateway allow-list rules",
        ]
      },
    ]
  },
  {
    id: "PB-02", icon: "🦠", title: "Ransomware Response",
    desc: "Critical playbook for ransomware detection, containment, and recovery.",
    tag: "critical",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor EDR for mass file rename/extension change",
          "Alert on shadow copy deletion via vssadmin",
          "Detect ransom note creation (README.txt patterns)",
          "Watch for unusual process trees (Office → cmd → PowerShell)",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Identify Patient Zero and initial infection vector",
          "Map scope of encrypted files and affected systems",
          "Determine ransomware family via extension and note",
          "Check for lateral movement via NTLM/PtH activity",
          "Review backup status and integrity",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "Immediately network-isolate affected hosts",
          "Disable compromised accounts in Active Directory",
          "Block C2 IP/domains at perimeter firewall",
          "Prevent backup share access from infected hosts",
          "Preserve forensic images before any remediation",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Validate clean backup copies before restoration",
          "Rebuild systems from known-good images",
          "Restore data from verified backups",
          "Re-image compromised endpoints",
          "Conduct post-recovery validation testing",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Implement 3-2-1 backup strategy with offline copy",
          "Enable application allowlisting on servers",
          "Restrict macro execution in Office applications",
          "Segment network to limit lateral movement blast radius",
          "Conduct regular ransomware tabletop exercises",
        ]
      },
    ]
  },
  {
    id: "PB-03", icon: "🔑", title: "Compromised Credentials",
    desc: "Response procedure for exposed or stolen user credentials.",
    tag: "high",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor threat intelligence for credential dumps",
          "Alert on impossible travel / impossible location logins",
          "Watch for login from Tor / VPN abuse patterns",
          "Correlate multiple failed logins followed by success",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Identify all accounts in the credential dump",
          "Review authentication logs for the affected period",
          "Check for new mail forwarding rules",
          "Audit recent file access and downloads",
          "Determine if credentials were reused on other systems",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "Force immediate password reset for affected accounts",
          "Invalidate all active sessions and tokens",
          "Enable MFA if not already active",
          "Block attacker source IPs at perimeter",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Verify account is clean after password reset",
          "Remove any persistence mechanisms (mail rules, OAuth grants)",
          "Monitor account for 72 hours post-incident",
          "Brief user on phishing and password hygiene",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Deploy enterprise password manager",
          "Enforce MFA for all accounts, especially admin",
          "Subscribe to HaveIBeenPwned API for bulk monitoring",
          "Implement Privileged Access Workstations (PAWs) for admins",
        ]
      },
    ]
  },
  {
    id: "PB-04", icon: "💻", title: "Malware / C2 Response",
    desc: "Handling active malware infections and command-and-control communications.",
    tag: "critical",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor for periodic network beaconing patterns",
          "Detect Office/PDF spawning command interpreter",
          "Alert on reflective DLL injection attempts",
          "Watch for unusual LSASS access (credential dumping)",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Perform live memory acquisition before isolation",
          "Analyze network traffic PCAP for C2 patterns",
          "Identify malware family via sandbox analysis",
          "Trace lateral movement indicators across the network",
          "Identify all compromised accounts on affected hosts",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "Network-isolate affected endpoints",
          "Block C2 domains and IPs at all control points",
          "Reset credentials of all accounts used on infected hosts",
          "Revoke authentication tokens and certificates",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Re-image affected endpoints from clean baseline",
          "Restore data from pre-compromise backups",
          "Validate removal via endpoint security scan",
          "Re-provision compromised credentials",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Enable EDR behavioral detection on all endpoints",
          "Implement network traffic analysis (NTA)",
          "Block script interpreter execution from Office applications",
          "Deploy DNS-layer security to block C2 domains",
        ]
      },
    ]
  },
  {
    id: "PB-05", icon: "💾", title: "Data Exfiltration Response",
    desc: "Detecting and responding to unauthorized data transfer events.",
    tag: "high",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor DLP alerts for bulk downloads and transfers",
          "Alert on abnormal DNS query lengths (tunneling)",
          "Watch for large outbound HTTPS transfers to new domains",
          "Track cloud storage sync to unmanaged accounts",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Classify the type of data that was exfiltrated",
          "Calculate volume and duration of the exfiltration",
          "Identify the exfiltration channel (DNS, HTTP, cloud, USB)",
          "Determine if data included PII, PHI, or IP",
          "Check regulatory notification requirements (GDPR, HIPAA)",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "Block exfiltration channel at network layer",
          "Suspend accounts involved in unauthorized transfer",
          "Remove access to sensitive data repositories",
          "Preserve all logs and evidence for legal hold",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Assess impact and notify affected data subjects if required",
          "Revoke any shared links or access tokens created",
          "Conduct privacy impact assessment",
          "Brief executive leadership and legal team",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Implement DLP policies on email and web proxy",
          "Monitor and alert on DNS query length anomalies",
          "Enforce Zero Trust network access principles",
          "Conduct regular data classification audits",
        ]
      },
    ]
  },
  {
    id: "PB-06", icon: "🏛️", title: "Insider Threat Response",
    desc: "Procedure for handling suspicious insider activity with legal compliance.",
    tag: "medium",
    phases: [
      {
        num: 1, label: "Detection", steps: [
          "Monitor UEBA for anomalous access patterns",
          "Track bulk downloads by terminating employees",
          "Alert on off-hours access to sensitive data",
          "Watch for USB device connection on secure segments",
        ]
      },
      {
        num: 2, label: "Investigation", steps: [
          "Collect and preserve digital evidence per legal hold",
          "Document timeline of suspicious activity",
          "Review access logs, downloads, email, and USB activity",
          "Engage HR and Legal before any user-facing actions",
          "Determine intent: malicious vs accidental",
        ]
      },
      {
        num: 3, label: "Containment", steps: [
          "With legal authorization: suspend account access",
          "Revoke access to sensitive data repositories",
          "Preserve forensic images of endpoints",
          "Notify management as directed by HR/Legal",
        ]
      },
      {
        num: 4, label: "Recovery", steps: [
          "Assess what data may have left the organization",
          "Notify affected parties per regulatory requirements",
          "Conduct post-incident lessons learned session",
        ]
      },
      {
        num: 5, label: "Prevention", steps: [
          "Implement formal offboarding security checklist",
          "Enable UEBA for early anomaly detection",
          "Apply least privilege principle to all data access",
          "Conduct regular access review for sensitive repositories",
        ]
      },
    ]
  },
];

const LEARNING_TOPICS = [
  {
    id: "LRN-01", icon: "📡",
    title: "What is a SIEM?",
    desc: "Security Information and Event Management — the core tool of every SOC.",
    level: "beginner",
    sections: [
      {
        heading: "Definition",
        body: "A SIEM (Security Information and Event Management) platform collects, aggregates, and correlates log data from across an organization's infrastructure to detect security threats in real-time. It combines Security Information Management (SIM) with Security Event Management (SEM)."
      },
      {
        heading: "How It Works",
        body: "Agents or connectors on endpoints, network devices, servers, and cloud platforms send logs to the SIEM. The SIEM normalizes this data into a common format, applies correlation rules, and generates alerts when suspicious patterns are detected."
      },
      {
        heading: "Key Capabilities",
        items: ["Log aggregation from hundreds of sources", "Real-time correlation rules and alerts", "User and Entity Behavior Analytics (UEBA)", "Threat intelligence integration", "Dashboards and reporting for compliance", "Incident ticketing and workflow integration"]
      },
      {
        heading: "Popular SIEM Platforms",
        items: ["Splunk Enterprise Security", "Microsoft Sentinel (Azure)", "IBM QRadar", "Elastic SIEM (ELK Stack)", "Chronicle (Google Cloud)"]
      },
      {
        heading: "SOC Analyst Use",
        body: "SOC analysts spend the majority of their day in the SIEM — writing detection rules, investigating alerts, building dashboards, and hunting for threats. Proficiency with a SIEM is the most essential skill for any Tier 1–3 SOC analyst."
      },
    ]
  },
  {
    id: "LRN-02", icon: "🕵️",
    title: "SOC Analyst Roles & Career Path",
    desc: "Understanding the tiers, responsibilities, and career progression in a SOC.",
    level: "beginner",
    sections: [
      {
        heading: "The SOC Analyst Tiers",
        items: [
          "Tier 1 – Alert Triage: Monitor alerts, triage false positives, escalate true positives.",
          "Tier 2 – Incident Response: Deep investigation, containment, and remediation of confirmed incidents.",
          "Tier 3 – Threat Hunting: Proactive hunting for hidden threats using advanced analytics.",
          "SOC Manager: Oversees team operations, reporting, and process improvement.",
        ]
      },
      {
        heading: "Core Skills",
        items: ["SIEM query writing (SPL, KQL, Sigma)", "Log analysis (Windows Event Logs, Syslog, VPC Flow)", "Network traffic analysis (Wireshark, Zeek)", "Malware triage and sandbox analysis", "Incident documentation and ticketing", "MITRE ATT&CK framework knowledge"]
      },
      {
        heading: "Recommended Certifications",
        items: ["CompTIA Security+ (entry level)", "CompTIA CySA+ (Tier 1–2 focus)", "GIAC GCIH – Incident Handler", "GIAC GCIA – Introspection Analyst", "Certified SOC Analyst (CSA) by EC-Council", "Microsoft SC-200 (Sentinel focused)"]
      },
      {
        heading: "Career Progression",
        body: "Most SOC analysts begin at Tier 1, developing speed and pattern recognition. With 1–2 years of experience, progression to Tier 2 is typical. Tier 3 / Threat Hunter roles require 3+ years and deeper technical expertise. SOC Leads and Managers typically have 5+ years of experience."
      },
    ]
  },
  {
    id: "LRN-03", icon: "🌐",
    title: "Networking Fundamentals for SOC",
    desc: "The network knowledge every SOC analyst needs to investigate threats.",
    level: "beginner",
    sections: [
      {
        heading: "Why Networking Matters in a SOC",
        body: "Most attacks involve network communication — C2 beaconing, lateral movement, data exfiltration, and reconnaissance. Understanding how networks work allows analysts to spot anomalies in traffic logs, firewall events, and DNS queries."
      },
      {
        heading: "Key Protocols to Know",
        items: ["TCP/IP – Foundation of internet communication", "DNS – Name resolution; often abused for C2 and exfiltration", "HTTP/HTTPS – Web traffic; analyze headers and payloads", "SMB – Windows file sharing; used in lateral movement", "LDAP/Kerberos – Active Directory authentication protocols", "ICMP – Ping; used in ping sweeps and covert channels"]
      },
      {
        heading: "Important Log Sources",
        items: ["Firewall logs – Connection allows and denies", "DNS logs – All name resolution requests", "DHCP logs – IP address assignments", "Proxy logs – Web browsing activity", "NetFlow / VPC Flow – IP-level traffic summaries", "IDS/IPS alerts – Signature-based detections"]
      },
      {
        heading: "SOC Network Analysis Techniques",
        items: ["Identify beaconing via periodic outbound connections", "Detect port scanning via fan-out from single source", "Spot lateral movement via unusual internal east-west traffic", "Find DNS tunneling via query length and frequency analysis"]
      },
    ]
  },
  {
    id: "LRN-04", icon: "🦠",
    title: "Malware Analysis Basics",
    desc: "How to classify, triage, and respond to malware incidents.",
    level: "intermediate",
    sections: [
      {
        heading: "Common Malware Types",
        items: ["Ransomware – Encrypts files and demands payment", "Trojans – Malicious software disguised as legitimate", "Rootkits – Hide malware from OS and security tools", "Keyloggers – Record keystrokes to steal credentials", "Worms – Self-propagating across networks", "Spyware – Silently monitor user activity", "Fileless Malware – Runs entirely in memory, no file on disk"]
      },
      {
        heading: "Static Analysis",
        body: "Examining malware without executing it. Techniques include: file hash lookup in threat intelligence databases (VirusTotal), string extraction to find hardcoded IPs/domains, PE header analysis to identify packing/obfuscation, and import table analysis to identify API calls."
      },
      {
        heading: "Dynamic Analysis",
        body: "Running malware in a controlled sandbox to observe behavior. Sandboxes like Any.run or Cuckoo capture: file system changes, registry modifications, network connections made, process creation events, and API call sequences."
      },
      {
        heading: "SOC Triage Checklist",
        items: ["Hash the sample and search VirusTotal", "Submit to sandbox for automated analysis", "Extract IOCs (IPs, domains, file hashes)", "Check IOCs against threat intelligence feeds", "Map behavior to MITRE ATT&CK techniques", "Determine scope of infection via EDR search"]
      },
    ]
  },
  {
    id: "LRN-05", icon: "🎣",
    title: "Phishing — Detection & Prevention",
    desc: "Understanding how phishing works and how to defend against it.",
    level: "beginner",
    sections: [
      {
        heading: "Types of Phishing",
        items: ["Phishing – Mass email campaigns to steal credentials", "Spear Phishing – Targeted attack against specific individuals", "Whaling – Targets C-level executives", "Vishing – Voice phishing via phone calls", "Smishing – SMS-based phishing attacks", "Business Email Compromise (BEC) – Impersonating trusted senders for fraud"]
      },
      {
        heading: "Technical Indicators",
        items: ["SPF FAIL – Sender not authorized for claimed domain", "DKIM FAIL – Email not cryptographically signed by domain", "DMARC reject/quarantine – Domain-level anti-spoofing policy", "Lookalike domain (corp-acme.net vs c0rp-acme.net)", "Recently registered domain (< 30 days old)", "Mismatched display name vs actual email address"]
      },
      {
        heading: "How to Analyze a Suspicious Email",
        items: ["View full email headers (not just the 'From' field)", "Check SPF/DKIM/DMARC results in headers", "Hover (don't click) links to see actual destination URL", "Search sender domain in threat intelligence (VirusTotal, Shodan)", "Sandbox any attachments before opening", "Compare link display text vs actual href"]
      },
      {
        heading: "Organizational Defenses",
        items: ["Implement DMARC with reject policy on your domain", "Enable email gateway advanced threat protection", "Run regular phishing simulations and training", "Configure external email banners in email client", "Deploy DNS-layer security to block phishing domains"]
      },
    ]
  },
  {
    id: "LRN-06", icon: "⚔️",
    title: "MITRE ATT&CK Framework",
    desc: "The definitive knowledge base for adversary tactics, techniques, and procedures.",
    level: "intermediate",
    sections: [
      {
        heading: "What is MITRE ATT&CK?",
        body: "MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge) is a globally accessible knowledge base of adversary behavior based on real-world observations. It describes the 14 tactics of an attack chain from Initial Access through Impact, with hundreds of specific techniques for each."
      },
      {
        heading: "The 14 Tactic Categories",
        items: ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
      },
      {
        heading: "How SOC Analysts Use ATT&CK",
        items: ["Tag alerts with ATT&CK technique IDs (e.g. T1566 = Phishing)", "Build detection rules aligned to specific techniques", "Map coverage gaps in your detection stack", "Write threat intelligence reports with standard taxonomy", "Use ATT&CK Navigator to visualize coverage and adversary profiles"]
      },
      {
        heading: "Example Mapping",
        items: ["Phishing email → T1566.001 Spearphishing Attachment", "Cobalt Strike beacon → T1071.001 C2 over HTTPS", "Mimikatz credential dump → T1003.001 LSASS Memory", "Ransomware file encryption → T1486 Data Encrypted for Impact", "Pass-the-Hash → T1550.002 Use Alternate Auth Material"]
      },
    ]
  },
];

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
const state = {
  currentSection: "overview",
  alertFilter: "all",
  alertSearch: "",
  missionScore: 0,
  completedMissions: new Set(),
  incidentStatuses: {},          // INC-id → status
  charts: {},
};

// pre-populate incident statuses
INCIDENTS.forEach(i => { state.incidentStatuses[i.id] = i.status; });

// ─────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────
function showSection(name) {
  state.currentSection = name;

  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  const sec = document.getElementById(`sec-${name}`);
  if (sec) sec.classList.add("active");

  const navItem = document.querySelector(`.nav-item[data-section="${name}"]`);
  if (navItem) navItem.classList.add("active");

  const titles = {
    overview: "Dashboard Overview",
    threats: "Threat Monitoring",
    incidents: "Incident Management",
    investigation: "Investigation Missions",
    playbooks: "Incident Response Playbooks",
    analytics: "Analytics & Reporting",
    learning: "Learning Center",
  };
  const pt = document.getElementById("pageTitle");
  if (pt) pt.textContent = titles[name] || name;

  // Render charts lazily on first visit
  if (name === "overview") { renderOverviewCharts(); renderOverviewAlerts(); }
  if (name === "analytics") { renderAnalyticsCharts(); }

  // close sidebar on mobile
  closeSidebar();

  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ─────────────────────────────────────────────
// SIDEBAR MOBILE
// ─────────────────────────────────────────────
function openSidebar() {
  document.getElementById("sidebar").classList.add("open");
  document.getElementById("sidebarOverlay").classList.add("active");
}
function closeSidebar() {
  document.getElementById("sidebar").classList.remove("open");
  document.getElementById("sidebarOverlay").classList.remove("active");
}

// ─────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────
function startClock() {
  function tick() {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, "0");
    const m = String(now.getMinutes()).padStart(2, "0");
    const s = String(now.getSeconds()).padStart(2, "0");
    const el = document.getElementById("timeDisplay");
    if (el) el.textContent = `${h}:${m}:${s} UTC`;
  }
  tick();
  setInterval(tick, 1000);
}

// ─────────────────────────────────────────────
// KPI COUNTERS
// ─────────────────────────────────────────────
function animateCounter(el, target, suffix = "") {
  let start = 0;
  const step = Math.ceil(target / 40);
  const timer = setInterval(() => {
    start = Math.min(start + step, target);
    el.textContent = start + suffix;
    if (start >= target) clearInterval(timer);
  }, 28);
}

function renderKPIs() {
  const total = ALERTS.length;
  const critical = ALERTS.filter(a => a.severity === "Critical").length;
  const resolved = INCIDENTS.filter(i => i.status === "Resolved").length;

  animateCounter(document.getElementById("kpiTotal"), total);
  animateCounter(document.getElementById("kpiCritical"), critical);
  animateCounter(document.getElementById("kpiResolved"), resolved);
  const el = document.getElementById("kpiResponse");
  if (el) { el.textContent = "--"; setTimeout(() => { el.textContent = "14m"; }, 600); }

  // badges
  const openAlerts = ALERTS.filter(a => a.status === "Open").length;
  document.getElementById("threatBadge").textContent = openAlerts;
  document.getElementById("incidentBadge").textContent =
    INCIDENTS.filter(i => i.status !== "Resolved" && i.status !== "Closed").length;
}

// ─────────────────────────────────────────────
// CANVAS CHARTS
// ─────────────────────────────────────────────

// Shared palette
const PAL = {
  cyan:   "#00d4ff",
  red:    "#ff3b5c",
  yellow: "#ffc533",
  green:  "#22d48a",
  orange: "#ff7a30",
  purple: "#a78bfa",
  blue:   "#3b82f6",
  text:   "#8ba3cc",
  grid:   "rgba(0,212,255,0.07)",
};

function drawBarChart(canvas, labels, values, colors, maxOverride) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth || canvas.width;
  const H = canvas.clientHeight || canvas.height;
  canvas.width = W * dpr; canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  const pad = { top: 20, right: 16, bottom: 38, left: 36 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top - pad.bottom;
  const max = maxOverride || Math.max(...values) * 1.15 || 10;
  const barW = Math.min(chartW / labels.length * 0.55, 40);

  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = PAL.grid; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH - (chartH * i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + chartW, y); ctx.stroke();
  }

  // Bars
  values.forEach((val, i) => {
    const x = pad.left + (chartW / labels.length) * i + (chartW / labels.length - barW) / 2;
    const barH = (val / max) * chartH;
    const y = pad.top + chartH - barH;
    const color = Array.isArray(colors) ? colors[i % colors.length] : colors;

    // Gradient fill
    const grad = ctx.createLinearGradient(0, y, 0, y + barH);
    grad.addColorStop(0, color);
    grad.addColorStop(1, color + "44");
    ctx.fillStyle = grad;
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, barW, barH, 3);
    } else {
      ctx.rect(x, y, barW, barH);
    }
    ctx.fill();

    // Value label
    ctx.fillStyle = color;
    ctx.font = `bold ${10 * dpr / dpr}px -apple-system, sans-serif`;
    ctx.textAlign = "center";
    ctx.fillText(val, x + barW / 2, y - 5);

    // X label
    ctx.fillStyle = PAL.text;
    ctx.font = `10px -apple-system, sans-serif`;
    ctx.fillText(labels[i], x + barW / 2, pad.top + chartH + 18);
  });

  // Y axis labels
  ctx.fillStyle = PAL.text; ctx.textAlign = "right"; ctx.font = "10px sans-serif";
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH - (chartH * i / 4);
    ctx.fillText(Math.round(max * i / 4), pad.left - 5, y + 4);
  }
}

function drawDonutChart(canvas, labels, values, colors) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth || canvas.width;
  const H = canvas.clientHeight || canvas.height;
  canvas.width = W * dpr; canvas.height = H * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  const total = values.reduce((a, b) => a + b, 0) || 1;
  const cx = W / 2 - 30;
  const cy = H / 2;
  const r = Math.min(cx, cy) * 0.72;
  const inner = r * 0.58;
  let angle = -Math.PI / 2;

  values.forEach((val, i) => {
    const slice = (val / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + slice);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.fill();
    angle += slice;
  });

  // Inner hole
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fillStyle = "#111d35";
  ctx.fill();

  // Center text
  ctx.fillStyle = PAL.cyan;
  ctx.font = `bold 18px sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(total, cx, cy);
  ctx.fillStyle = PAL.text;
  ctx.font = `10px sans-serif`;
  ctx.fillText("total", cx, cy + 14);

  // Legend
  const legX = W - 80;
  labels.forEach((lbl, i) => {
    const ly = cy - (labels.length * 18 / 2) + i * 20;
    ctx.fillStyle = colors[i % colors.length];
    ctx.fillRect(legX, ly, 10, 10);
    ctx.fillStyle = PAL.text;
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    ctx.textBaseline = "top";
    ctx.fillText(`${lbl} (${values[i]})`, legX + 14, ly);
  });
}

function drawLineChart(canvas, labels, datasets) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth || canvas.width;
  const H = canvas.clientHeight || canvas.height;
  canvas.width = W * dpr; canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  const pad = { top: 18, right: 20, bottom: 34, left: 36 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top - pad.bottom;
  const allVals = datasets.flatMap(d => d.data);
  const max = Math.max(...allVals) * 1.2 || 10;

  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = PAL.grid; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH - (chartH * i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + chartW, y); ctx.stroke();
  }

  // Y axis labels
  ctx.fillStyle = PAL.text; ctx.textAlign = "right"; ctx.font = "10px sans-serif";
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH - (chartH * i / 4);
    ctx.fillText(Math.round(max * i / 4), pad.left - 5, y + 4);
  }

  // X axis labels
  ctx.fillStyle = PAL.text; ctx.textAlign = "center"; ctx.font = "10px sans-serif";
  labels.forEach((lbl, i) => {
    const x = pad.left + (chartW / (labels.length - 1)) * i;
    ctx.fillText(lbl, x, pad.top + chartH + 18);
  });

  // Lines
  datasets.forEach(ds => {
    const pts = ds.data.map((val, i) => ({
      x: pad.left + (chartW / (ds.data.length - 1)) * i,
      y: pad.top + chartH - (val / max) * chartH,
    }));

    // Area fill
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pad.top + chartH);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length - 1].x, pad.top + chartH);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    grad.addColorStop(0, ds.color + "44");
    grad.addColorStop(1, ds.color + "00");
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = ds.color;
    ctx.lineWidth = 2;
    ctx.stroke();

    // Dots
    pts.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = ds.color;
      ctx.fill();
    });
  });
}

function renderOverviewCharts() {
  const catCanvas = document.getElementById("chartCategories");
  const sevCanvas = document.getElementById("chartSeverity");
  const trendCanvas = document.getElementById("chartTrends");
  if (!catCanvas || !sevCanvas || !trendCanvas) return;

  // Categories
  const catCounts = {};
  ALERTS.forEach(a => { catCounts[a.type] = (catCounts[a.type] || 0) + 1; });
  const catLabels = Object.keys(catCounts);
  const catVals = Object.values(catCounts);
  const catColors = [PAL.red, PAL.cyan, PAL.orange, PAL.yellow, PAL.green, PAL.purple, PAL.blue];
  drawBarChart(catCanvas, catLabels.map(l => l.length > 8 ? l.slice(0, 7) + "…" : l), catVals, catColors);

  // Severity donut
  const sevLabels = ["Critical", "High", "Medium", "Low"];
  const sevVals = sevLabels.map(s => ALERTS.filter(a => a.severity === s).length);
  const sevColors = [PAL.red, PAL.orange, PAL.yellow, PAL.green];
  drawDonutChart(sevCanvas, sevLabels, sevVals, sevColors);

  // Trends (last 7 days, synthetic)
  const trendLabels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  drawLineChart(trendCanvas, trendLabels, [
    { data: [8, 14, 11, 17, 22, 9, 12], color: PAL.red, label: "Alerts" },
    { data: [3, 5, 4, 8, 7, 2, 4], color: PAL.green, label: "Resolved" },
  ]);
}

function renderAnalyticsCharts() {
  const vecCanvas = document.getElementById("chartVectors");
  const hourCanvas = document.getElementById("chartHourly");
  const resCanvas = document.getElementById("chartResolution");
  if (!vecCanvas || !hourCanvas || !resCanvas) return;

  drawBarChart(vecCanvas,
    ["Email", "Web", "RDP", "USB", "Supply\nChain", "VPN"],
    [34, 22, 15, 8, 6, 15],
    [PAL.red, PAL.orange, PAL.yellow, PAL.purple, PAL.cyan, PAL.blue]
  );

  drawLineChart(hourCanvas,
    ["00","02","04","06","08","10","12","14","16","18","20","22"],
    [{ data: [2,1,1,3,6,14,18,15,12,10,7,4], color: PAL.cyan }]
  );

  drawLineChart(resCanvas,
    ["Week 1","Week 2","Week 3","Week 4","Week 5","Week 6","Week 7"],
    [
      { data: [65, 70, 72, 68, 80, 85, 88], color: PAL.green, label: "Resolution %" },
      { data: [22, 18, 20, 25, 16, 14, 11], color: PAL.red, label: "Open Incidents" },
    ]
  );
}

// ─────────────────────────────────────────────
// ALERT LIST
// ─────────────────────────────────────────────
function getSeverityOrder(s) { return { Critical: 0, High: 1, Medium: 2, Low: 3 }[s] ?? 4; }

function getFilteredAlerts() {
  return ALERTS
    .filter(a => state.alertFilter === "all" || a.severity === state.alertFilter)
    .filter(a => {
      const q = state.alertSearch.toLowerCase();
      return !q || a.title.toLowerCase().includes(q) ||
        a.type.toLowerCase().includes(q) ||
        a.source.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q);
    })
    .sort((a, b) => getSeverityOrder(a.severity) - getSeverityOrder(b.severity));
}

function renderAlertList() {
  const filtered = getFilteredAlerts();
  const container = document.getElementById("alertList");
  if (!container) return;
  container.innerHTML = "";

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><p>No alerts match your current filters.</p></div>`;
    return;
  }

  filtered.forEach((alert, idx) => {
    const item = document.createElement("div");
    item.className = `alert-item sev-${alert.severity}`;
    item.style.animationDelay = `${idx * 0.04}s`;
    item.innerHTML = `
      <span class="alert-sev-badge badge-${alert.severity}">${alert.severity}</span>
      <div class="alert-info">
        <div class="alert-title">${alert.title}</div>
        <div class="alert-meta">${alert.type} · Src: ${alert.source} · ${alert.id}</div>
      </div>
      <span class="alert-time">${alert.time.split(" ")[1]}</span>
      <span class="alert-status-pill status-${alert.status.replace(" ", "")}">${alert.status}</span>
    `;
    item.addEventListener("click", () => openAlertModal(alert));
    container.appendChild(item);
  });
}

function renderOverviewAlerts() {
  const container = document.getElementById("overviewAlertList");
  if (!container) return;
  container.innerHTML = "";
  ALERTS.slice(0, 6).forEach((alert, idx) => {
    const item = document.createElement("div");
    item.className = `alert-item sev-${alert.severity}`;
    item.style.animationDelay = `${idx * 0.05}s`;
    item.innerHTML = `
      <span class="alert-sev-badge badge-${alert.severity}">${alert.severity}</span>
      <div class="alert-info">
        <div class="alert-title">${alert.title}</div>
        <div class="alert-meta">${alert.type} · ${alert.id}</div>
      </div>
      <span class="alert-time">${alert.time.split(" ")[1]}</span>
      <span class="alert-status-pill status-${alert.status.replace(" ", "")}">${alert.status}</span>
    `;
    item.addEventListener("click", () => openAlertModal(alert));
    container.appendChild(item);
  });
}

// ─────────────────────────────────────────────
// ALERT MODAL
// ─────────────────────────────────────────────
function openAlertModal(alert) {
  const content = document.getElementById("alertModalContent");
  content.innerHTML = `
    <div class="alert-modal-header">
      <h3>${alert.title}</h3>
      <div class="alert-modal-meta">
        <span class="alert-sev-badge badge-${alert.severity}">${alert.severity}</span>
        <span class="alert-status-pill status-${alert.status.replace(" ", "")}">${alert.status}</span>
        <span style="font-size:11px;color:var(--text-muted)">${alert.id}</span>
      </div>
    </div>

    <div class="detail-grid">
      <div class="detail-field"><label>Type</label><span>${alert.type}</span></div>
      <div class="detail-field"><label>Time</label><span>${alert.time}</span></div>
      <div class="detail-field"><label>Source</label><span>${alert.source}</span></div>
      <div class="detail-field"><label>Destination</label><span>${alert.dest}</span></div>
      <div class="detail-field"><label>Analyst</label><span>${alert.analyst}</span></div>
      <div class="detail-field"><label>MITRE ATT&CK</label><span>${alert.mitre}</span></div>
    </div>

    <div class="alert-detail-section">
      <h4>Description</h4>
      <p>${alert.description}</p>
    </div>

    <div class="alert-detail-section">
      <h4>Indicators of Compromise (IOC)</h4>
      <ul>${alert.indicators.map(i => `<li>${i}</li>`).join("")}</ul>
    </div>

    <div class="alert-detail-section">
      <h4>Recommended Actions</h4>
      <ul>${alert.recommendations.map(r => `<li>${r}</li>`).join("")}</ul>
    </div>

    <div style="margin-top:16px;padding:10px 14px;background:rgba(255,197,51,.07);border:1px solid rgba(255,197,51,.2);border-radius:6px;font-size:11px;color:var(--yellow)">
      ⚠ This alert is part of a simulated training environment. All data is fictional.
    </div>
  `;
  openModal("alertModal");
}

// ─────────────────────────────────────────────
// INCIDENT LIST
// ─────────────────────────────────────────────
function renderIncidentList() {
  const container = document.getElementById("incidentList");
  if (!container) return;
  container.innerHTML = "";

  INCIDENTS.forEach((inc, idx) => {
    const status = state.incidentStatuses[inc.id] || inc.status;
    const card = document.createElement("div");
    card.className = "incident-card";
    card.style.animationDelay = `${idx * 0.06}s`;
    card.innerHTML = `
      <div>
        <div class="incident-id">${inc.id}</div>
        <div class="incident-title">${inc.title}</div>
        <div class="incident-desc">${inc.description}</div>
        <div class="incident-meta">
          <span><span class="alert-sev-badge badge-${inc.severity}" style="font-size:9px">${inc.severity}</span></span>
          <span>📅 Created: ${inc.created}</span>
          <span>👤 ${inc.assignee}</span>
          <span>🖥 ${inc.affectedSystems}</span>
        </div>
      </div>
      <div class="incident-actions">
        <span class="alert-status-pill status-${status.replace(" ", "")}" id="status-${inc.id}">${status}</span>
        ${status !== "Resolved" && status !== "Closed"
          ? `<button class="btn-sm btn-green" onclick="updateIncidentStatus('${inc.id}', 'Resolved')">✓ Resolve</button>
             <button class="btn-sm btn-cyan" onclick="updateIncidentStatus('${inc.id}', 'Investigating')">🔍 Investigate</button>`
          : `<button class="btn-sm btn-cyan" onclick="updateIncidentStatus('${inc.id}', 'Open')">↺ Reopen</button>`
        }
      </div>
    `;
    container.appendChild(card);
  });
}

function updateIncidentStatus(id, newStatus) {
  state.incidentStatuses[id] = newStatus;
  renderIncidentList();
  // Also update KPI
  renderKPIs();
}

// ─────────────────────────────────────────────
// MISSIONS
// ─────────────────────────────────────────────
function renderMissionList() {
  const container = document.getElementById("missionList");
  if (!container) return;
  container.innerHTML = "";
  document.getElementById("missionTotal").textContent = MISSIONS.length;
  document.getElementById("missionCompleted").textContent = state.completedMissions.size;
  document.getElementById("missionScore").textContent = state.missionScore;

  MISSIONS.forEach((m, idx) => {
    const done = state.completedMissions.has(m.id);
    const card = document.createElement("div");
    card.className = `mission-card${done ? " completed" : ""}`;
    card.style.animationDelay = `${idx * 0.07}s`;
    card.innerHTML = `
      <div class="mission-info">
        <div class="mission-tag">${m.tag}</div>
        <div class="mission-title">${m.title}</div>
        <div class="mission-desc">${m.desc}</div>
      </div>
      ${done
        ? `<div class="mission-completed-badge">✓ Completed +${m.points}pts</div>`
        : `<button class="btn-start-mission" onclick="openMissionModal('${m.id}')">▶ Start Mission</button>`
      }
    `;
    container.appendChild(card);
  });
}

function openMissionModal(id) {
  const mission = MISSIONS.find(m => m.id === id);
  if (!mission) return;

  let answered = false;

  function renderMission() {
    const content = document.getElementById("missionModalContent");
    content.innerHTML = `
      <div class="mission-modal-header">
        <div class="mission-tag">${mission.tag}</div>
        <h3>${mission.title}</h3>
        <p>${mission.desc}</p>
      </div>

      <div class="mission-scenario">${mission.scenario.replace(/\n/g, "<br>")}</div>

      <div class="mission-question">${mission.question}</div>

      <div class="mission-options" id="missionOptions">
        ${mission.options.map((opt, i) => `
          <button class="mission-option" data-idx="${i}" onclick="selectOption('${id}', ${i}, this)">
            ${opt.text}
          </button>
        `).join("")}
      </div>

      <div id="missionFeedbackArea"></div>

      <div style="font-size:11px;color:var(--text-muted);margin-top:8px">
        ⚠ Fictional training scenario · ${mission.points} points available
      </div>
    `;
  }

  renderMission();
  openModal("missionModal");

  // expose to global scope for onclick
  window.selectOption = function(mId, optIdx, btn) {
    if (answered) return;
    answered = true;

    const m = MISSIONS.find(x => x.id === mId);
    if (!m) return;

    const opt = m.options[optIdx];

    // Disable all options
    document.querySelectorAll(".mission-option").forEach((b, i) => {
      b.disabled = true;
      if (m.options[i].correct) b.classList.add("correct");
    });
    if (!opt.correct) btn.classList.add("incorrect");

    // Feedback
    const fb = document.getElementById("missionFeedbackArea");
    fb.innerHTML = `
      <div class="mission-feedback ${opt.correct ? "feedback-correct" : "feedback-wrong"}">
        ${opt.feedback}
      </div>
      ${opt.correct ? `<div style="margin-bottom:6px"><span class="score-point">+${m.points} pts</span></div>` : ""}
      <button class="btn-next-mission" onclick="closeMissionAndScore('${mId}', ${opt.correct})">
        ${opt.correct ? "✓ Claim Points & Close" : "✕ Close & Retry Later"}
      </button>
    `;
  };

  window.closeMissionAndScore = function(mId, wasCorrect) {
    if (wasCorrect && !state.completedMissions.has(mId)) {
      const m = MISSIONS.find(x => x.id === mId);
      state.completedMissions.add(mId);
      state.missionScore += m.points;
    }
    closeModal("missionModal");
    renderMissionList();
  };
}

// ─────────────────────────────────────────────
// PLAYBOOKS
// ─────────────────────────────────────────────
function renderPlaybooks() {
  const container = document.getElementById("playbookList");
  if (!container) return;
  container.innerHTML = "";

  PLAYBOOKS.forEach((pb, idx) => {
    const card = document.createElement("div");
    card.className = "playbook-card";
    card.style.animationDelay = `${idx * 0.06}s`;
    card.innerHTML = `
      <div class="playbook-icon">${pb.icon}</div>
      <div class="playbook-title">${pb.title}</div>
      <div class="playbook-desc">${pb.desc}</div>
      <span class="playbook-tag tag-${pb.tag}">${pb.tag.toUpperCase()}</span>
    `;
    card.addEventListener("click", () => openPlaybookModal(pb));
    container.appendChild(card);
  });
}

function openPlaybookModal(pb) {
  const content = document.getElementById("playbookModalContent");
  const phaseColors = ["phase-1", "phase-2", "phase-3", "phase-4", "phase-5"];
  const phaseIcons = ["🔍", "🔬", "🔒", "♻️", "🛡️"];

  content.innerHTML = `
    <div class="playbook-modal-header">
      <span style="font-size:28px">${pb.icon}</span>
      <h3>${pb.title}</h3>
    </div>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:18px">${pb.desc}</p>
    <div class="playbook-phases">
      ${pb.phases.map((phase, i) => `
        <div class="phase-item ${phaseColors[i] || ""}">
          <div class="phase-title">
            <span>${phaseIcons[i] || "▸"}</span>
            <span>Phase ${phase.num}: ${phase.label}</span>
          </div>
          <ul class="phase-steps">
            ${phase.steps.map(s => `<li>${s}</li>`).join("")}
          </ul>
        </div>
      `).join("")}
    </div>
  `;
  openModal("playbookModal");
}

// ─────────────────────────────────────────────
// LEARNING CENTER
// ─────────────────────────────────────────────
function renderLearning() {
  const container = document.getElementById("learningList");
  if (!container) return;
  container.innerHTML = "";

  LEARNING_TOPICS.forEach((topic, idx) => {
    const card = document.createElement("div");
    card.className = "learn-card";
    card.style.animationDelay = `${idx * 0.06}s`;
    card.innerHTML = `
      <div class="learn-card-icon">${topic.icon}</div>
      <div class="learn-card-title">${topic.title}</div>
      <div class="learn-card-desc">${topic.desc}</div>
      <span class="learn-card-level level-${topic.level}">${topic.level.charAt(0).toUpperCase() + topic.level.slice(1)}</span>
    `;
    card.addEventListener("click", () => openLearningModal(topic));
    container.appendChild(card);
  });
}

function openLearningModal(topic) {
  const content = document.getElementById("learningModalContent");
  content.innerHTML = `
    <div class="learn-modal-header">
      <span style="font-size:28px">${topic.icon}</span>
      <div>
        <h3>${topic.title}</h3>
        <span class="learn-card-level level-${topic.level}">${topic.level.charAt(0).toUpperCase() + topic.level.slice(1)}</span>
      </div>
    </div>
    <div class="glow-divider"></div>
    ${topic.sections.map(sec => `
      <div class="learn-section">
        <h4>${sec.heading}</h4>
        ${sec.body ? `<p>${sec.body}</p>` : ""}
        ${sec.items ? `<ul>${sec.items.map(i => `<li>${i}</li>`).join("")}</ul>` : ""}
      </div>
    `).join("")}
  `;
  openModal("learningModal");
}

// ─────────────────────────────────────────────
// MODAL HELPERS
// ─────────────────────────────────────────────
function openModal(id) {
  document.getElementById(id).classList.add("active");
  document.body.style.overflow = "hidden";
}
function closeModal(id) {
  document.getElementById(id).classList.remove("active");
  document.body.style.overflow = "";
}

// ─────────────────────────────────────────────
// EVENT LISTENERS
// ─────────────────────────────────────────────
function bindEvents() {
  // Sidebar navigation
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", e => {
      e.preventDefault();
      showSection(item.dataset.section);
    });
  });

  // View all link
  document.querySelectorAll(".view-all-link[data-section]").forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      showSection(link.dataset.section);
    });
  });

  // Mobile menu toggle
  document.getElementById("menuToggle").addEventListener("click", () => {
    const sidebar = document.getElementById("sidebar");
    if (sidebar.classList.contains("open")) closeSidebar();
    else openSidebar();
  });

  // Sidebar overlay click
  document.getElementById("sidebarOverlay").addEventListener("click", closeSidebar);

  // Modal close buttons
  document.getElementById("alertModalClose").addEventListener("click", () => closeModal("alertModal"));
  document.getElementById("missionModalClose").addEventListener("click", () => closeModal("missionModal"));
  document.getElementById("playbookModalClose").addEventListener("click", () => closeModal("playbookModal"));
  document.getElementById("learningModalClose").addEventListener("click", () => closeModal("learningModal"));

  // Close modals on overlay click
  document.querySelectorAll(".modal-overlay").forEach(overlay => {
    overlay.addEventListener("click", e => {
      if (e.target === overlay) {
        overlay.classList.remove("active");
        document.body.style.overflow = "";
      }
    });
  });

  // Alert search
  const searchInput = document.getElementById("alertSearch");
  if (searchInput) {
    searchInput.addEventListener("input", e => {
      state.alertSearch = e.target.value;
      renderAlertList();
    });
  }

  // Alert filter buttons
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.alertFilter = btn.dataset.filter;
      renderAlertList();
    });
  });

  // Keyboard close modals
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-overlay.active").forEach(m => {
        m.classList.remove("active");
        document.body.style.overflow = "";
      });
    }
  });
}

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
function init() {
  startClock();
  renderKPIs();
  renderAlertList();
  renderOverviewAlerts();
  renderIncidentList();
  renderMissionList();
  renderPlaybooks();
  renderLearning();
  renderOverviewCharts();
  bindEvents();
}

document.addEventListener("DOMContentLoaded", init);
