#!/usr/bin/env python3
"""
Simple test server to debug POST requests
"""

import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import os

class TestHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Set the directory to serve static files from
        os.chdir(str(Path(__file__).parent / "osint_tool" / "web_static"))
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle API POST requests"""
        print(f"POST request to: {self.path}")
        print(f"Headers: {dict(self.headers)}")
        
        if self.path.startswith('/api/'):
            try:
                # Read the request body
                content_length = int(self.headers.get('Content-Length', 0))
                print(f"Content length: {content_length}")
                
                if content_length > 0:
                    body = self.rfile.read(content_length)
                    print(f"Body: {body}")
                    data = json.loads(body.decode('utf-8'))
                    print(f"Parsed data: {data}")
                else:
                    data = {}
                
                # Send a simple response
                response = {"status": "success", "message": f"Received POST to {self.path}", "data": data}
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                print(f"Error: {e}")
                self.send_error(500, f"Server error: {str(e)}")
        else:
            self.send_error(404, "API endpoint not found")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_test_server(port=8000):
    """Run the test HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, TestHTTPRequestHandler)
    print(f"Test server running on http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()

if __name__ == '__main__':
    run_test_server()
