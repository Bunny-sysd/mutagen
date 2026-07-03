import sys
import subprocess
import struct

class SecureTaskProcessor:
    def __init__(self):
        # Secure default state
        self.is_admin = False
        self.task_queue = []
        self.log_file = "/tmp/process.log"

    def process_payload(self, payload: bytes):
        """
        Parses a custom binary protocol:
        [1 byte opcode] [2 byte length] [data...]
        """
        idx = 0
        while idx < len(payload):
            if idx + 3 > len(payload):
                break
            
            opcode = payload[idx]
            length = struct.unpack(">H", payload[idx+1:idx+3])[0]
            idx += 3
            
            if idx + length > len(payload):
                break
                
            data = payload[idx:idx+length]
            idx += length
            
            # --- INSTRUCTION SET ---
            
            if opcode == 0x10:  # Add task to queue
                self.task_queue.append(data.decode('utf-8', errors='ignore'))
                
            elif opcode == 0x20:  # Update configuration
                # VULNERABILITY: Arbitrary Attribute Overwrite
                # Expected format: b"log_file=/new/path.log"
                try:
                    key, val = data.decode('utf-8').split('=', 1)
                    
                    # The flaw: No validation on which attributes can be modified.
                    # It blindly updates ANY class attribute if it exists.
                    if hasattr(self, key):
                        attr_type = type(getattr(self, key))
                        
                        # Handle boolean conversion for state flags
                        if attr_type == bool:
                            set_val = val.lower() == 'true'
                        else:
                            set_val = attr_type(val)
                            
                        setattr(self, key, set_val)
                except Exception:
                    pass
                    
            elif opcode == 0x30:  # Execute queue
                self._run_tasks()

    def _run_tasks(self):
        for task in self.task_queue:
            if self.is_admin:
                # Privileged execution path (Vulnerable if is_admin is hijacked)
                subprocess.run(task, shell=True)
            else:
                # Safe execution path
                print(f"Logging task to {self.log_file}: {task}")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
        
    processor = SecureTaskProcessor()
    processor.process_payload(data)