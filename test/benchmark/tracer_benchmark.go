package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// TracerBenchmark provides comprehensive benchmarking for the eBPF tracer
type TracerBenchmark struct {
	tracerCmd     *exec.Cmd
	serverCmd     *exec.Cmd
	monitor       *SystemMonitor
	testDuration  time.Duration
	requestRate   int
	concurrency   int
	results       *BenchmarkResults
}

// BenchmarkResults holds comprehensive benchmark results
type BenchmarkResults struct {
	TestName          string
	Duration          time.Duration
	RequestsSent      uint64
	RequestsSucceeded uint64
	RequestsFailed    uint64
	EventsGenerated   uint64
	AvgLatency        time.Duration
	MinLatency        time.Duration
	MaxLatency        time.Duration
	P95Latency        time.Duration
	P99Latency        time.Duration
	Throughput        float64
	ErrorRate         float64
	SystemMetrics     *PerformanceSummary
}

// NewTracerBenchmark creates a new tracer benchmark
func NewTracerBenchmark() *TracerBenchmark {
	return &TracerBenchmark{
		testDuration: 60 * time.Second,
		requestRate:  100,
		concurrency:  10,
	}
}

// SetParameters configures benchmark parameters
func (tb *TracerBenchmark) SetParameters(duration time.Duration, requestRate, concurrency int) {
	tb.testDuration = duration
	tb.requestRate = requestRate
	tb.concurrency = concurrency
}

// StartTracer starts the eBPF tracer process
func (tb *TracerBenchmark) StartTracer() error {
	// Start the tracer
	tb.tracerCmd = exec.Command("../../build/http-tracer")
	
	err := tb.tracerCmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start tracer: %v", err)
	}
	
	// Initialize system monitor
	tb.monitor = NewSystemMonitor(tb.tracerCmd.Process.Pid)
	err = tb.monitor.Start()
	if err != nil {
		tb.StopTracer()
		return fmt.Errorf("failed to start system monitor: %v", err)
	}
	
	// Wait for tracer to initialize
	time.Sleep(3 * time.Second)
	
	return nil
}

// StartTestServer starts the test HTTP server
func (tb *TracerBenchmark) StartTestServer() error {
	tb.serverCmd = exec.Command("python3", "../flask_server.py")
	tb.serverCmd.Dir = "../../test"
	
	err := tb.serverCmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start test server: %v", err)
	}
	
	// Wait for server to be ready
	time.Sleep(2 * time.Second)
	
	// Test server connectivity
	resp, err := http.Get("http://localhost:5000/health")
	if err != nil {
		tb.StopTestServer()
		return fmt.Errorf("test server not responding: %v", err)
	}
	resp.Body.Close()
	
	return nil
}

// RunBenchmark executes the benchmark test
func (tb *TracerBenchmark) RunBenchmark(testName string) (*BenchmarkResults, error) {
	results := &BenchmarkResults{
		TestName:    testName,
		MinLatency:  time.Hour, // Initialize to high value
		MaxLatency:  0,
	}
	
	// Start monitoring
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	defer monitorCancel()
	
	go tb.monitorPerformance(monitorCtx)
	
	// Run load test
	start := time.Now()
	latencies := tb.runLoadTest()
	results.Duration = time.Since(start)
	
	// Calculate latency statistics
	if len(latencies) > 0 {
		results.AvgLatency = tb.calculateAverageLatency(latencies)
		results.MinLatency = tb.findMinLatency(latencies)
		results.MaxLatency = tb.findMaxLatency(latencies)
		results.P95Latency = tb.calculatePercentile(latencies, 95)
		results.P99Latency = tb.calculatePercentile(latencies, 99)
	}
	
	// Get system metrics
	results.SystemMetrics = tb.monitor.GetSummary()
	
	// Calculate throughput and error rate
	results.Throughput = float64(results.RequestsSucceeded) / results.Duration.Seconds()
	if results.RequestsSent > 0 {
		results.ErrorRate = float64(results.RequestsFailed) / float64(results.RequestsSent) * 100
	}
	
	tb.results = results
	return results, nil
}

// runLoadTest executes the actual load test
func (tb *TracerBenchmark) runLoadTest() []time.Duration {
	var requestsSent, requestsSucceeded, requestsFailed uint64
	var latencies []time.Duration
	var latencyMutex sync.Mutex
	
	// Create context for test duration
	ctx, cancel := context.WithTimeout(context.Background(), tb.testDuration)
	defer cancel()
	
	// Calculate request interval
	requestInterval := time.Second / time.Duration(tb.requestRate)
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < tb.concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			
			ticker := time.NewTicker(requestInterval * time.Duration(tb.concurrency))
			defer ticker.Stop()
			
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					start := time.Now()
					atomic.AddUint64(&requestsSent, 1)
					
					// Make HTTP request
					resp, err := client.Get(fmt.Sprintf("http://localhost:5000/api/bench/%d", workerID))
					latency := time.Since(start)
					
					if err != nil {
						atomic.AddUint64(&requestsFailed, 1)
					} else {
						resp.Body.Close()
						atomic.AddUint64(&requestsSucceeded, 1)
						
						// Record latency
						latencyMutex.Lock()
						latencies = append(latencies, latency)
						latencyMutex.Unlock()
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	// Update results
	tb.results = &BenchmarkResults{
		RequestsSent:      atomic.LoadUint64(&requestsSent),
		RequestsSucceeded: atomic.LoadUint64(&requestsSucceeded),
		RequestsFailed:    atomic.LoadUint64(&requestsFailed),
	}
	
	return latencies
}

// monitorPerformance continuously monitors system performance
func (tb *TracerBenchmark) monitorPerformance(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tb.monitor.Sample()
		}
	}
}

// calculateAverageLatency calculates the average latency
func (tb *TracerBenchmark) calculateAverageLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, latency := range latencies {
		total += latency
	}
	
	return total / time.Duration(len(latencies))
}

// findMinLatency finds the minimum latency
func (tb *TracerBenchmark) findMinLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	min := latencies[0]
	for _, latency := range latencies[1:] {
		if latency < min {
			min = latency
		}
	}
	
	return min
}

// findMaxLatency finds the maximum latency
func (tb *TracerBenchmark) findMaxLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	max := latencies[0]
	for _, latency := range latencies[1:] {
		if latency > max {
			max = latency
		}
	}
	
	return max
}

// calculatePercentile calculates the specified percentile
func (tb *TracerBenchmark) calculatePercentile(latencies []time.Duration, percentile int) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	// Simple percentile calculation (would use proper sorting in production)
	index := (len(latencies) * percentile) / 100
	if index >= len(latencies) {
		index = len(latencies) - 1
	}
	
	return latencies[index]
}

// StopTracer stops the tracer process
func (tb *TracerBenchmark) StopTracer() {
	if tb.tracerCmd != nil && tb.tracerCmd.Process != nil {
		tb.tracerCmd.Process.Signal(syscall.SIGTERM)
		tb.tracerCmd.Wait()
	}
}

// StopTestServer stops the test server
func (tb *TracerBenchmark) StopTestServer() {
	if tb.serverCmd != nil && tb.serverCmd.Process != nil {
		tb.serverCmd.Process.Signal(syscall.SIGTERM)
		tb.serverCmd.Wait()
	}
}

// PrintResults prints the benchmark results
func (br *BenchmarkResults) PrintResults() {
	fmt.Printf("\n=== Benchmark Results: %s ===\n", br.TestName)
	fmt.Printf("Duration: %v\n", br.Duration)
	fmt.Printf("Requests Sent: %d\n", br.RequestsSent)
	fmt.Printf("Requests Succeeded: %d\n", br.RequestsSucceeded)
	fmt.Printf("Requests Failed: %d\n", br.RequestsFailed)
	fmt.Printf("Throughput: %.2f req/sec\n", br.Throughput)
	fmt.Printf("Error Rate: %.2f%%\n", br.ErrorRate)
	fmt.Println()
	
	fmt.Println("Latency Statistics:")
	fmt.Printf("  Average: %v\n", br.AvgLatency)
	fmt.Printf("  Minimum: %v\n", br.MinLatency)
	fmt.Printf("  Maximum: %v\n", br.MaxLatency)
	fmt.Printf("  95th Percentile: %v\n", br.P95Latency)
	fmt.Printf("  99th Percentile: %v\n", br.P99Latency)
	fmt.Println()
	
	if br.SystemMetrics != nil {
		fmt.Println("System Performance:")
		fmt.Printf("  Average CPU: %.2f%%\n", br.SystemMetrics.AverageCPU)
		fmt.Printf("  Peak CPU: %.2f%%\n", br.SystemMetrics.PeakCPU)
		fmt.Printf("  Average Memory: %.2f MB\n", br.SystemMetrics.AverageMemory/1024/1024)
		fmt.Printf("  Peak Memory: %.2f MB\n", br.SystemMetrics.PeakMemory/1024/1024)
		fmt.Printf("  Memory Overhead: %.2f MB\n", br.SystemMetrics.MemoryOverhead/1024/1024)
	}
}

// SaveResults saves benchmark results to a file
func (br *BenchmarkResults) SaveResults(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "Benchmark Results: %s\n", br.TestName)
	fmt.Fprintf(file, "=========================\n")
	fmt.Fprintf(file, "Duration: %v\n", br.Duration)
	fmt.Fprintf(file, "Requests Sent: %d\n", br.RequestsSent)
	fmt.Fprintf(file, "Requests Succeeded: %d\n", br.RequestsSucceeded)
	fmt.Fprintf(file, "Requests Failed: %d\n", br.RequestsFailed)
	fmt.Fprintf(file, "Throughput: %.2f req/sec\n", br.Throughput)
	fmt.Fprintf(file, "Error Rate: %.2f%%\n", br.ErrorRate)
	fmt.Fprintf(file, "Average Latency: %v\n", br.AvgLatency)
	fmt.Fprintf(file, "95th Percentile Latency: %v\n", br.P95Latency)
	fmt.Fprintf(file, "99th Percentile Latency: %v\n", br.P99Latency)
	
	if br.SystemMetrics != nil {
		fmt.Fprintf(file, "Average CPU: %.2f%%\n", br.SystemMetrics.AverageCPU)
		fmt.Fprintf(file, "Peak CPU: %.2f%%\n", br.SystemMetrics.PeakCPU)
		fmt.Fprintf(file, "Average Memory: %.2f MB\n", br.SystemMetrics.AverageMemory/1024/1024)
		fmt.Fprintf(file, "Memory Overhead: %.2f MB\n", br.SystemMetrics.MemoryOverhead/1024/1024)
	}
	
	return nil
}
