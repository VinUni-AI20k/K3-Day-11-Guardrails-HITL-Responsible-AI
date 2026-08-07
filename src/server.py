"""
VinBank AI Security Live Chat Server
Serves the UI folder and exposes the real chat agent via /api/chat
"""
import os
import sys
import json
import asyncio
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

# Ensure src/ is on sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.config import setup_api_key
setup_api_key()

from agents.agent import create_unsafe_agent
from agents.guards_agent import create_guards_agent, check_secret_leak
from core.utils import chat_with_agent
from attacks.attacks import classify_attack_outcome

# Initialize agents globally
print("Initializing VinBank Agents...")
unsafe_agent, unsafe_runner = create_unsafe_agent()
guards_agent, guards_runner = create_guards_agent()

UI_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ui"))

class ChatRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Override the directory to point to the UI folder
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == '/api/chat':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                message = data.get('message', '').strip()
                mode = data.get('mode', 'guards')
                session_id = data.get('session_id')

                if not message:
                    self.send_error_response("Message cannot be empty")
                    return

                if mode == 'unsafe':
                    response, session = asyncio.run(
                        chat_with_agent(unsafe_agent, unsafe_runner, message, session_id=session_id)
                    )
                else:
                    response, session = asyncio.run(
                        chat_with_agent(guards_agent, guards_runner, message, session_id=session_id)
                    )
                
                # Classify the outcome using the official test suite method
                outcome = classify_attack_outcome(message, response, target_name=mode)
                blocked = outcome.get('blocked', False) or outcome.get('blocked_input', False)
                leaked = outcome.get('leaked', False)
                layer = outcome.get('layer')

                response_data = {
                    "response": response,
                    "session_id": session.id if session else None,
                    "blocked": blocked,
                    "leaked": leaked,
                    "layer": layer
                }

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode('utf-8'))

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_error_response(str(e))
        else:
            self.send_error(404, "Not Found")

    def send_error_response(self, error_msg):
        self.send_response(500)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"error": error_msg}).encode('utf-8'))

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, ChatRequestHandler)
    print(f"\n==============================================================")
    print(f"VinBank AI Security Demo Server running at: http://localhost:{port}")
    print(f"==============================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()

if __name__ == '__main__':
    run_server()
