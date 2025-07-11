package benchmark

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SystemMonitor provides system-level performance monitoring
type SystemMonitor struct {
	pid           int
	startTime     time.Time
	initialStats  *ProcessStats
	samplingRate  time.Duration
	samples       []*ProcessStats
}

// ProcessStats holds process-specific performance statistics
type ProcessStats struct {
	Timestamp    time.Time
	PID          int
	CPUPercent   float64
	MemoryRSS    uint64 // Resident Set Size in bytes
	MemoryVSZ    uint64 // Virtual Memory Size in bytes
	ThreadCount  int
	FileHandles  int
	ContextSwitches uint64
	SystemCalls  uint64
}

// NewSystemMonitor creates a new system monitor for a specific process
func NewSystemMonitor(pid int) *SystemMonitor {
	return &SystemMonitor{
		pid:          pid,
		samplingRate: 1 * time.Second,
		samples:      make([]*ProcessStats, 0),
	}
}

// Start begins monitoring the specified process
func (sm *SystemMonitor) Start() error {
	sm.startTime = time.Now()
	
	// Get initial stats
	stats, err := sm.getProcessStats()
	if err != nil {
		return fmt.Errorf("failed to get initial process stats: %v", err)
	}
	sm.initialStats = stats
	
	return nil
}

// Sample takes a performance sample
func (sm *SystemMonitor) Sample() error {
	stats, err := sm.getProcessStats()
	if err != nil {
		return err
	}
	
	sm.samples = append(sm.samples, stats)
	return nil
}

// GetSummary returns a performance summary
func (sm *SystemMonitor) GetSummary() *PerformanceSummary {
	if len(sm.samples) == 0 {
		return nil
	}
	
	summary := &PerformanceSummary{
		Duration:     time.Since(sm.startTime),
		SampleCount:  len(sm.samples),
		InitialStats: sm.initialStats,
		FinalStats:   sm.samples[len(sm.samples)-1],
	}
	
	// Calculate averages and peaks
	var totalCPU, totalMemory float64
	var peakCPU, peakMemory float64
	
	for _, sample := range sm.samples {
		totalCPU += sample.CPUPercent
		totalMemory += float64(sample.MemoryRSS)
		
		if sample.CPUPercent > peakCPU {
			peakCPU = sample.CPUPercent
		}
		if float64(sample.MemoryRSS) > peakMemory {
			peakMemory = float64(sample.MemoryRSS)
		}
	}
	
	summary.AverageCPU = totalCPU / float64(len(sm.samples))
	summary.AverageMemory = totalMemory / float64(len(sm.samples))
	summary.PeakCPU = peakCPU
	summary.PeakMemory = peakMemory
	
	// Calculate overhead
	if sm.initialStats != nil {
		summary.CPUOverhead = summary.AverageCPU
		summary.MemoryOverhead = float64(summary.FinalStats.MemoryRSS - sm.initialStats.MemoryRSS)
	}
	
	return summary
}

// PerformanceSummary contains performance analysis results
type PerformanceSummary struct {
	Duration       time.Duration
	SampleCount    int
	InitialStats   *ProcessStats
	FinalStats     *ProcessStats
	AverageCPU     float64
	AverageMemory  float64
	PeakCPU        float64
	PeakMemory     float64
	CPUOverhead    float64
	MemoryOverhead float64
}

// getProcessStats retrieves current process statistics from /proc
func (sm *SystemMonitor) getProcessStats() (*ProcessStats, error) {
	stats := &ProcessStats{
		Timestamp: time.Now(),
		PID:       sm.pid,
	}
	
	// Read /proc/[pid]/stat for basic process info
	statFile := fmt.Sprintf("/proc/%d/stat", sm.pid)
	statData, err := os.ReadFile(statFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", statFile, err)
	}
	
	// Parse stat file (simplified parsing)
	statFields := strings.Fields(string(statData))
	if len(statFields) < 24 {
		return nil, fmt.Errorf("invalid stat file format")
	}
	
	// Parse memory info (RSS is field 24, VSZ is field 23)
	if rss, err := strconv.ParseUint(statFields[23], 10, 64); err == nil {
		stats.MemoryRSS = rss * 4096 // Convert pages to bytes (assuming 4KB pages)
	}
	if vsz, err := strconv.ParseUint(statFields[22], 10, 64); err == nil {
		stats.MemoryVSZ = vsz
	}
	
	// Parse thread count (field 20)
	if threads, err := strconv.Atoi(statFields[19]); err == nil {
		stats.ThreadCount = threads
	}
	
	// Get CPU usage from /proc/[pid]/stat
	stats.CPUPercent = sm.calculateCPUPercent(statFields)
	
	// Get file descriptor count
	stats.FileHandles = sm.getFileDescriptorCount()
	
	// Get context switches and system calls
	stats.ContextSwitches, stats.SystemCalls = sm.getAdvancedStats()
	
	return stats, nil
}

// calculateCPUPercent calculates CPU usage percentage
func (sm *SystemMonitor) calculateCPUPercent(statFields []string) float64 {
	// This is a simplified CPU calculation
	// In production, would need to track changes over time
	// For now, return a placeholder value
	return 0.0
}

// getFileDescriptorCount counts open file descriptors
func (sm *SystemMonitor) getFileDescriptorCount() int {
	fdDir := fmt.Sprintf("/proc/%d/fd", sm.pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// getAdvancedStats retrieves context switches and system call counts
func (sm *SystemMonitor) getAdvancedStats() (uint64, uint64) {
	statusFile := fmt.Sprintf("/proc/%d/status", sm.pid)
	file, err := os.Open(statusFile)
	if err != nil {
		return 0, 0
	}
	defer file.Close()
	
	var contextSwitches, systemCalls uint64
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "voluntary_ctxt_switches:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					contextSwitches += val
				}
			}
		} else if strings.HasPrefix(line, "nonvoluntary_ctxt_switches:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					contextSwitches += val
				}
			}
		}
	}
	
	return contextSwitches, systemCalls
}

// PrintSummary prints a formatted performance summary
func (ps *PerformanceSummary) PrintSummary() {
	fmt.Println("=== Performance Summary ===")
	fmt.Printf("Duration: %v\n", ps.Duration)
	fmt.Printf("Samples: %d\n", ps.SampleCount)
	fmt.Println()
	
	fmt.Println("CPU Usage:")
	fmt.Printf("  Average: %.2f%%\n", ps.AverageCPU)
	fmt.Printf("  Peak: %.2f%%\n", ps.PeakCPU)
	fmt.Printf("  Overhead: %.2f%%\n", ps.CPUOverhead)
	fmt.Println()
	
	fmt.Println("Memory Usage:")
	fmt.Printf("  Average: %.2f MB\n", ps.AverageMemory/1024/1024)
	fmt.Printf("  Peak: %.2f MB\n", ps.PeakMemory/1024/1024)
	fmt.Printf("  Overhead: %.2f MB\n", ps.MemoryOverhead/1024/1024)
	fmt.Println()
	
	if ps.InitialStats != nil && ps.FinalStats != nil {
		fmt.Println("Process Stats:")
		fmt.Printf("  Initial Threads: %d -> Final Threads: %d\n", 
			ps.InitialStats.ThreadCount, ps.FinalStats.ThreadCount)
		fmt.Printf("  Initial FDs: %d -> Final FDs: %d\n", 
			ps.InitialStats.FileHandles, ps.FinalStats.FileHandles)
		fmt.Printf("  Context Switches: %d\n", ps.FinalStats.ContextSwitches)
	}
}

// SaveToFile saves the performance summary to a file
func (ps *PerformanceSummary) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "Performance Summary\n")
	fmt.Fprintf(file, "==================\n")
	fmt.Fprintf(file, "Duration: %v\n", ps.Duration)
	fmt.Fprintf(file, "Samples: %d\n", ps.SampleCount)
	fmt.Fprintf(file, "Average CPU: %.2f%%\n", ps.AverageCPU)
	fmt.Fprintf(file, "Peak CPU: %.2f%%\n", ps.PeakCPU)
	fmt.Fprintf(file, "CPU Overhead: %.2f%%\n", ps.CPUOverhead)
	fmt.Fprintf(file, "Average Memory: %.2f MB\n", ps.AverageMemory/1024/1024)
	fmt.Fprintf(file, "Peak Memory: %.2f MB\n", ps.PeakMemory/1024/1024)
	fmt.Fprintf(file, "Memory Overhead: %.2f MB\n", ps.MemoryOverhead/1024/1024)
	
	return nil
}

// CompareWithBaseline compares current performance with a baseline
func (ps *PerformanceSummary) CompareWithBaseline(baseline *PerformanceSummary) *PerformanceComparison {
	return &PerformanceComparison{
		Current:           ps,
		Baseline:          baseline,
		CPUDifference:     ps.AverageCPU - baseline.AverageCPU,
		MemoryDifference:  ps.AverageMemory - baseline.AverageMemory,
		DurationDifference: ps.Duration - baseline.Duration,
	}
}

// PerformanceComparison holds comparison results between two performance summaries
type PerformanceComparison struct {
	Current            *PerformanceSummary
	Baseline           *PerformanceSummary
	CPUDifference      float64
	MemoryDifference   float64
	DurationDifference time.Duration
}

// PrintComparison prints the performance comparison
func (pc *PerformanceComparison) PrintComparison() {
	fmt.Println("=== Performance Comparison ===")
	fmt.Printf("CPU Usage: %.2f%% (baseline: %.2f%%, diff: %+.2f%%)\n", 
		pc.Current.AverageCPU, pc.Baseline.AverageCPU, pc.CPUDifference)
	fmt.Printf("Memory Usage: %.2f MB (baseline: %.2f MB, diff: %+.2f MB)\n", 
		pc.Current.AverageMemory/1024/1024, pc.Baseline.AverageMemory/1024/1024, 
		pc.MemoryDifference/1024/1024)
	fmt.Printf("Duration: %v (baseline: %v, diff: %+v)\n", 
		pc.Current.Duration, pc.Baseline.Duration, pc.DurationDifference)
}
