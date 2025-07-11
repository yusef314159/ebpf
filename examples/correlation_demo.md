# eBPF HTTP Tracing - Correlation Demo

This document demonstrates how the eBPF HTTP tracer correlates inbound HTTP requests with outbound connections (e.g., database calls, API calls).

## How Correlation Works

### 1. Request ID Generation
When an HTTP request is detected in the `read()` syscall:
- A unique `request_id` is generated using an atomic counter
- The request context (ID, method, path, PID) is stored in the `active_requests` map

### 2. Outbound Connection Correlation
When a `connect()` syscall is detected:
- The tracer looks up the active request context for the current PID
- If found, the outbound connection is tagged with the same `request_id`
- This creates a correlation between the inbound HTTP request and outbound connections

### 3. Event Types
- **Type 0 (accept)**: New incoming connection
- **Type 1 (read)**: HTTP request detected (generates request_id)
- **Type 2 (connect)**: Outbound connection (correlated with request_id if available)

## Sample Trace Output

Here's what you'll see when running the tracer:

### 1. HTTP Request Received
```json
{
  "timestamp": "2024-01-15T10:30:45.123456789Z",
  "request_id": 1001,
  "pid": 12345,
  "tid": 12345,
  "comm": "python3",
  "method": "GET",
  "path": "/users",
  "payload_len": 85,
  "payload": "GET /users HTTP/1.1\r\nHost: localhost:5000\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n",
  "event_type": "read",
  "event_type_id": 1,
  "protocol": "TCP"
}
```

### 2. Database Connection (Correlated)
```json
{
  "timestamp": "2024-01-15T10:30:45.125123456Z",
  "request_id": 1001,
  "pid": 12345,
  "tid": 12345,
  "comm": "python3",
  "method": "GET",
  "path": "/users",
  "event_type": "connect",
  "event_type_id": 2,
  "protocol": "TCP"
}
```

### 3. External API Call (Correlated)
```json
{
  "timestamp": "2024-01-15T10:30:45.127890123Z",
  "request_id": 1001,
  "pid": 12345,
  "tid": 12345,
  "comm": "python3",
  "method": "GET",
  "path": "/users",
  "event_type": "connect",
  "event_type_id": 2,
  "protocol": "TCP"
}
```

## Testing Correlation

### 1. Start the Test Environment
```bash
# Terminal 1: Start Flask server
make test-server

# Terminal 2: Start eBPF tracer
sudo make run

# Terminal 3: Generate test traffic
make test
```

### 2. Observe Correlation
Look for events with the same `request_id`:
- One `read` event (HTTP request)
- Multiple `connect` events (outbound connections)

### 3. Flask Server Endpoints That Trigger Outbound Connections

#### `/users` - Database Queries
```bash
curl http://localhost:5000/users
```
This triggers SQLite database connections that will show up as correlated `connect` events.

#### `/external` - External API Calls
```bash
curl http://localhost:5000/external
```
This makes HTTP requests to httpbin.org, creating outbound connections correlated with the original request.

#### `/slow` - Multiple Database Operations
```bash
curl http://localhost:5000/slow
```
This performs multiple database queries, showing several correlated `connect` events.

## Advanced Correlation Features

### 5-Tuple Tracking (Future Enhancement)
The current implementation includes structures for 5-tuple tracking:

```c
struct connection_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};
```

This can be enhanced to:
1. Extract actual IP addresses and ports from socket addresses
2. Track connection state across multiple syscalls
3. Correlate connections across different processes

### Request Lifecycle Tracking
Future enhancements could track:
- Request start/end times
- Total processing duration
- Number of outbound connections per request
- Error rates and timeouts

## Limitations

### Current Limitations
1. **PID-based correlation**: Only correlates within the same process
2. **No IP address extraction**: Socket addresses not parsed yet
3. **Simple request ID**: Uses basic counter (not distributed-safe)
4. **No cleanup**: Active requests map grows indefinitely

### Planned Improvements
1. **Cross-process correlation**: Track requests across process boundaries
2. **Socket address parsing**: Extract real IP addresses and ports
3. **Request cleanup**: Remove completed requests from tracking maps
4. **Distributed request IDs**: Use UUIDs or distributed ID generation

## Debugging Correlation

### Check Active Requests
You can inspect the eBPF maps using `bpftool`:

```bash
# List all eBPF programs
sudo bpftool prog list

# Show map contents (replace MAP_ID with actual ID)
sudo bpftool map dump id MAP_ID
```

### Troubleshooting

1. **No correlation seen**: 
   - Ensure the Flask server is making actual outbound connections
   - Check that the same PID is making both HTTP and outbound calls

2. **Missing request IDs**:
   - Verify HTTP parsing is working (check for method/path in logs)
   - Ensure the request counter map is initialized

3. **Too many events**:
   - Adjust the logging filter in the Go program
   - Add PID filtering to focus on specific processes

## Example Analysis

Here's how to analyze a correlated trace:

```bash
# Run tracer and save output
sudo ./build/http-tracer > trace.log

# Filter by request ID
grep '"request_id": 1001' trace.log

# Count events per request
grep -o '"request_id": [0-9]*' trace.log | sort | uniq -c

# Analyze timing
grep '"request_id": 1001' trace.log | jq '.timestamp, .event_type'
```

This correlation capability enables powerful distributed tracing scenarios where you can track a single HTTP request through all its downstream dependencies.
