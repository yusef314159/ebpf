#!/usr/bin/env python3
"""
Simple Flask test server for eBPF HTTP tracing PoC.
Simulates a backend service with database calls.
"""

import time
import random
import sqlite3
import os
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Initialize SQLite database
DB_PATH = '/tmp/test_db.sqlite'

def init_db():
    """Initialize test database with sample data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    cursor.execute('DELETE FROM users')  # Clear existing data
    sample_users = [
        ('Alice Johnson', 'alice@example.com'),
        ('Bob Smith', 'bob@example.com'),
        ('Charlie Brown', 'charlie@example.com'),
        ('Diana Prince', 'diana@example.com'),
    ]
    
    cursor.executemany('INSERT INTO users (name, email) VALUES (?, ?)', sample_users)
    conn.commit()
    conn.close()

def simulate_db_query(query_type="SELECT"):
    """Simulate database operation with realistic delay."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if query_type == "SELECT":
        cursor.execute('SELECT * FROM users ORDER BY RANDOM() LIMIT 1')
        result = cursor.fetchone()
    elif query_type == "INSERT":
        name = f"User_{random.randint(1000, 9999)}"
        email = f"user{random.randint(1000, 9999)}@example.com"
        cursor.execute('INSERT INTO users (name, email) VALUES (?, ?)', (name, email))
        conn.commit()
        result = cursor.lastrowid
    
    conn.close()
    
    # Simulate network/DB latency
    time.sleep(random.uniform(0.01, 0.05))
    return result

def simulate_external_api_call():
    """Simulate calling an external service."""
    try:
        # This will create an outbound connection that our eBPF tracer can detect
        response = requests.get('http://httpbin.org/delay/1', timeout=2)
        return {"status": "success", "data": response.json()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.route('/')
def home():
    """Simple home endpoint."""
    return jsonify({
        "message": "eBPF HTTP Tracing Test Server",
        "timestamp": time.time(),
        "endpoints": ["/users", "/users/<id>", "/health", "/slow", "/external"]
    })

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": time.time()})

@app.route('/users', methods=['GET', 'POST'])
def users():
    """Users endpoint with database interaction."""
    if request.method == 'GET':
        # Simulate multiple DB queries
        users_data = []
        for _ in range(random.randint(1, 3)):
            user = simulate_db_query("SELECT")
            if user:
                users_data.append({
                    "id": user[0],
                    "name": user[1],
                    "email": user[2],
                    "created_at": user[3]
                })
        
        return jsonify({
            "users": users_data,
            "count": len(users_data),
            "timestamp": time.time()
        })
    
    elif request.method == 'POST':
        # Create new user
        user_id = simulate_db_query("INSERT")
        return jsonify({
            "message": "User created",
            "user_id": user_id,
            "timestamp": time.time()
        }), 201

@app.route('/users/<int:user_id>')
def get_user(user_id):
    """Get specific user by ID."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            "id": user[0],
            "name": user[1],
            "email": user[2],
            "created_at": user[3]
        })
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/slow')
def slow_endpoint():
    """Endpoint that simulates slow processing."""
    # Multiple database operations
    for _ in range(3):
        simulate_db_query("SELECT")
    
    # Simulate processing time
    time.sleep(random.uniform(0.1, 0.3))
    
    return jsonify({
        "message": "Slow operation completed",
        "processing_time": "simulated",
        "timestamp": time.time()
    })

@app.route('/external')
def external_call():
    """Endpoint that makes external API calls."""
    result = simulate_external_api_call()
    return jsonify({
        "message": "External API call completed",
        "result": result,
        "timestamp": time.time()
    })

@app.route('/data', methods=['POST'])
def post_data():
    """Endpoint for testing POST requests with JSON data."""
    data = request.get_json()
    
    # Simulate processing the data
    simulate_db_query("INSERT")
    
    return jsonify({
        "message": "Data processed successfully",
        "received_data": data,
        "timestamp": time.time()
    })

if __name__ == '__main__':
    print("Initializing test database...")
    init_db()
    print("Starting Flask test server...")
    print("Available endpoints:")
    print("  GET  /")
    print("  GET  /health")
    print("  GET  /users")
    print("  POST /users")
    print("  GET  /users/<id>")
    print("  GET  /slow")
    print("  GET  /external")
    print("  POST /data")
    print("\nServer running on http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
