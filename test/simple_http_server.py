#!/usr/bin/env python3
"""
Simple HTTP Server for UET Testing
==================================

This demonstrates UET's language-agnostic tracing capabilities.
UET will capture all HTTP traffic from this Python server without any code modification.

Usage:
    python3 simple_http_server.py

Then in another terminal:
    curl http://localhost:8080/api/users/123
    curl -X POST http://localhost:8080/api/users -d '{"name":"John"}'
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

class UETTestHandler(BaseHTTPRequestHandler):
    """HTTP handler that generates various types of requests for UET to trace"""
    
    def log_message(self, format, *args):
        """Custom logging to show what UET should capture"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {format % args}")
    
    def do_GET(self):
        """Handle GET requests - UET will trace these"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        
        print(f"🔍 UET SHOULD CAPTURE: GET {path}")
        
        # Simulate different API endpoints
        if path == "/api/users":
            self.send_users_list()
        elif path.startswith("/api/users/"):
            user_id = path.split("/")[-1]
            self.send_user_detail(user_id)
        elif path == "/api/health":
            self.send_health_check()
        elif path == "/api/slow":
            self.send_slow_response()
        else:
            self.send_not_found()
    
    def do_POST(self):
        """Handle POST requests - UET will trace these"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        print(f"🔍 UET SHOULD CAPTURE: POST {path} (body: {len(post_data)} bytes)")
        
        if path == "/api/users":
            self.create_user(post_data)
        elif path == "/api/login":
            self.handle_login(post_data)
        else:
            self.send_not_found()
    
    def send_users_list(self):
        """Send list of users"""
        users = [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
            {"id": 3, "name": "Charlie", "email": "charlie@example.com"}
        ]
        
        response = {
            "users": users,
            "total": len(users),
            "timestamp": datetime.now().isoformat()
        }
        
        self.send_json_response(200, response)
    
    def send_user_detail(self, user_id):
        """Send specific user details"""
        try:
            uid = int(user_id)
            if uid == 123:  # Special test user
                user = {
                    "id": 123,
                    "name": "Test User",
                    "email": "test@example.com",
                    "profile": {
                        "age": 30,
                        "location": "San Francisco",
                        "preferences": ["coding", "coffee", "eBPF"]
                    },
                    "last_login": datetime.now().isoformat()
                }
                self.send_json_response(200, user)
            else:
                self.send_json_response(404, {"error": "User not found"})
        except ValueError:
            self.send_json_response(400, {"error": "Invalid user ID"})
    
    def send_health_check(self):
        """Send health check response"""
        health = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": time.time() - server_start_time,
            "version": "1.0.0"
        }
        self.send_json_response(200, health)
    
    def send_slow_response(self):
        """Send a slow response to test UET timing capture"""
        print("⏱️  UET SHOULD CAPTURE: Slow response timing")
        time.sleep(2)  # Simulate slow processing
        
        response = {
            "message": "This was a slow response",
            "processing_time_seconds": 2,
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)
    
    def create_user(self, post_data):
        """Handle user creation"""
        try:
            user_data = json.loads(post_data)
            new_user = {
                "id": 999,  # Mock ID
                "name": user_data.get("name", "Unknown"),
                "email": user_data.get("email", "unknown@example.com"),
                "created_at": datetime.now().isoformat()
            }
            self.send_json_response(201, new_user)
        except json.JSONDecodeError:
            self.send_json_response(400, {"error": "Invalid JSON"})
    
    def handle_login(self, post_data):
        """Handle login request"""
        try:
            login_data = json.loads(post_data)
            username = login_data.get("username")
            password = login_data.get("password")
            
            # Mock authentication
            if username == "admin" and password == "secret":
                response = {
                    "success": True,
                    "token": "mock_jwt_token_12345",
                    "expires_in": 3600,
                    "user": {"id": 1, "username": "admin", "role": "administrator"}
                }
                self.send_json_response(200, response)
            else:
                self.send_json_response(401, {"error": "Invalid credentials"})
        except json.JSONDecodeError:
            self.send_json_response(400, {"error": "Invalid JSON"})
    
    def send_not_found(self):
        """Send 404 response"""
        self.send_json_response(404, {"error": "Endpoint not found"})
    
    def send_json_response(self, status_code, data):
        """Send JSON response"""
        json_data = json.dumps(data, indent=2)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(json_data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(json_data.encode('utf-8'))
        
        print(f"📤 UET SHOULD CAPTURE: Response {status_code} ({len(json_data)} bytes)")

def run_server(port=8080):
    """Run the HTTP server"""
    global server_start_time
    server_start_time = time.time()
    
    server_address = ('', port)
    httpd = HTTPServer(server_address, UETTestHandler)
    
    print("🚀 UET Test HTTP Server Starting")
    print("=" * 40)
    print(f"📡 Server running on http://localhost:{port}")
    print("🔍 UET will capture all HTTP traffic to this server")
    print()
    print("Test endpoints:")
    print(f"  GET  http://localhost:{port}/api/users")
    print(f"  GET  http://localhost:{port}/api/users/123")
    print(f"  GET  http://localhost:{port}/api/health")
    print(f"  GET  http://localhost:{port}/api/slow")
    print(f"  POST http://localhost:{port}/api/users")
    print(f"  POST http://localhost:{port}/api/login")
    print()
    print("Example curl commands:")
    print(f"  curl http://localhost:{port}/api/users/123")
    print(f"  curl -X POST http://localhost:{port}/api/users -d '{{\"name\":\"John\"}}'")
    print(f"  curl -X POST http://localhost:{port}/api/login -d '{{\"username\":\"admin\",\"password\":\"secret\"}}'")
    print()
    print("🎯 Start UET in another terminal to see tracing in action!")
    print("=" * 40)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
        httpd.shutdown()

if __name__ == "__main__":
    run_server()
