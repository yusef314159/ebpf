gcc -o test_app -g test.c && ./test_app

# sample output

# {
#   "timestamp": "2025-07-13T02:13:21.123456789Z",
#   "tracer_type": "stack",
#   "pid": 1234,
#   "tid": 5678,
#   "comm": "python3",
#   "stack_id": 42,
#   "stack_depth": 5,
#   "instruction_pointer": "0x7fff12345678",
#   "duration_ns": 1500000
# }