"""CyberShield AI — Safe Shutdown Script
Safely stops only the backend (Python) and frontend (Node) processes
listening on ports 8000 and 5173 without affecting any unrelated system processes.
"""

import subprocess
import sys

def stop_process_on_port(port: int, expected_process_names: list) -> int:
    terminated = 0
    try:
        output = subprocess.check_output("netstat -ano", shell=True).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Error querying netstat: {e}")
        return 0

    seen_pids = set()
    for line in output.splitlines():
        if f":{port}" in line and ("LISTENING" in line or "ESTABLISHED" in line):
            parts = line.strip().split()
            if len(parts) >= 5:
                pid_str = parts[-1]
                if pid_str.isdigit():
                    pid = int(pid_str)
                    if pid > 4 and pid not in seen_pids:
                        seen_pids.add(pid)
                        # Verify process name before killing
                        try:
                            t_out = subprocess.check_output(f'tasklist /FI "PID eq {pid}" /NH', shell=True).decode("utf-8", errors="ignore")
                            proc_name = t_out.strip().split()[0].lower()
                            if any(exp in proc_name for exp in expected_process_names):
                                print(f"[STOPPING] Terminating {proc_name} on port {port} (PID: {pid})...")
                                subprocess.call(f"taskkill /PID {pid} /F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                terminated += 1
                        except Exception:
                            pass
    return terminated

if __name__ == "__main__":
    print("[INFO] Checking active CyberShield AI server processes...")
    b_count = stop_process_on_port(8000, ["python"])
    f_count = stop_process_on_port(5173, ["node"])
    if b_count == 0 and f_count == 0:
        print("[INFO] No active processes found on ports 8000 or 5173.")
    else:
        print(f"[OK] Successfully stopped {b_count} backend and {f_count} frontend processes.")

