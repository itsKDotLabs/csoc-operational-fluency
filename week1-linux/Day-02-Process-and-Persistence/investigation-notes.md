# Reverse Shell Artifact Analysis

## Process Tree

Observed:

- nc 172.31.x.x 4444
- Parent: interactive shell
- User: `ssm-user`

Used:

```bash
ps -ef --forest
```

---

## Network Correlation

Observed:
```plain text
ESTAB 172.31.33.159:48630 → 172.31.19.30:4444
```
- 48630 = ephemeral source port selected by target OS
- 4444 = attacker listener port
- Socket owned by nc

Used:
```bash
ss -antp | grep 4444
```

---

## Auditd Telemetry

Used:
```bash
sudo ausearch -m EXECVE | grep -E "mkfifo|nc|bash"
```
Confirmed:
- Execution of mkfifo
- Execution of nc
- Shell invocation

---

## Observations

- ESTAB indicates active C2 session
- LISTEN state indicates server-side bind
- Ephemeral ports are OS-assigned, not attacker-defined
- Port 443 would reduce suspicion at network layer but not process layer