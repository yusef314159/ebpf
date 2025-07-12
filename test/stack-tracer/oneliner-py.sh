# In another terminal, run some applications to generate stack traces
# The stack tracer captures function calls, memory allocations, etc.

# Example: Run a simple program
python3 -c "
import time
def recursive_func(n):
    if n <= 0: return 1
    time.sleep(0.01)
    return n * recursive_func(n-1)
print(recursive_func(10))
"