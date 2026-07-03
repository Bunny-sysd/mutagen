import sys
import os
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

class VulnerableHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        # Route handler for /ping
        if parsed_url.path == "/ping":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            ip_list = query_params.get("ip")
            
            if ip_list:
                ip = ip_list[0]
                
                # Vulnerable command execution
                # Directly concatenates query param into system shell call
                cmd = f"ping -n 1 {ip}"
                print(f"Executing command: {cmd}")
                
                status = os.system(cmd)
                
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                
                if status == 0:
                    self.wfile.write(b"Ping succeeded\n")
                else:
                    self.wfile.write(b"Ping failed\n")
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Missing ip query parameter\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    # Silence standard logging to keep test outputs clean
    def log_message(self, format, *args):
        pass

def run():
    server_address = ('127.0.0.1', 5000)
    httpd = HTTPServer(server_address, VulnerableHTTPHandler)
    print("Vulnerable HTTP Server running on http://127.0.0.1:5000...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
