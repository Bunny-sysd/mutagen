import sys
import os

def run_ping(ip):
    # Vulnerable command execution
    # Directly concatenates input into os.system shell string
    cmd = f"ping -n 1 {ip}"
    print(f"Running: {cmd}")
    status = os.system(cmd)
    if status != 0:
        print("Ping failed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_ping(sys.argv[1])
    else:
        print("Usage: python target.py <ip>")
