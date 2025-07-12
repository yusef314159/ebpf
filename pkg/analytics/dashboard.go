package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// startDashboard starts the web dashboard
func (ae *AnalyticsEngine) startDashboard(ctx context.Context) {
	defer ae.wg.Done()

	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/metrics", ae.handleMetrics)
	mux.HandleFunc("/api/health", ae.handleHealth)
	mux.HandleFunc("/api/alerts", ae.handleAlerts)
	mux.HandleFunc("/api/processors", ae.handleProcessors)
	mux.HandleFunc("/api/stats", ae.handleStats)

	// Dashboard UI
	mux.HandleFunc("/", ae.handleDashboard)
	mux.HandleFunc("/dashboard", ae.handleDashboard)

	// Static assets (embedded)
	mux.HandleFunc("/static/", ae.handleStatic)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", ae.config.DashboardPort),
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}

// handleMetrics handles the metrics API endpoint
func (ae *AnalyticsEngine) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get query parameters
	windowParam := r.URL.Query().Get("window")
	window := 5 * time.Minute // Default window
	if windowParam != "" {
		if parsedWindow, err := time.ParseDuration(windowParam); err == nil {
			window = parsedWindow
		}
	}

	// Get metrics from all aggregators
	allMetrics := make(map[string]interface{})

	ae.mutex.RLock()
	for name, aggregator := range ae.aggregators {
		metrics, err := aggregator.GetMetrics(window)
		if err == nil {
			allMetrics[name] = metrics
		}
	}
	ae.mutex.RUnlock()

	// Add current metrics from metric store
	allMetrics["current"] = ae.metricStore.GetCurrentMetrics()

	json.NewEncoder(w).Encode(allMetrics)
}

// handleHealth handles the health check endpoint
func (ae *AnalyticsEngine) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ae.GetHealthStatus())
}

// handleAlerts handles the alerts API endpoint
func (ae *AnalyticsEngine) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if ae.alertManager == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
			"message": "Alerting is not enabled",
		})
		return
	}

	response := map[string]interface{}{
		"enabled":        true,
		"active_alerts":  ae.alertManager.GetActiveAlerts(),
		"alert_history":  ae.alertManager.GetAlertHistory(50),
		"alert_stats":    ae.alertManager.GetAlertStats(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleProcessors handles the processors API endpoint
func (ae *AnalyticsEngine) handleProcessors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	processors := make(map[string]interface{})
	ae.mutex.RLock()
	for name, processor := range ae.processors {
		processors[name] = processor.Metrics()
	}
	ae.mutex.RUnlock()

	json.NewEncoder(w).Encode(processors)
}

// handleStats handles the statistics API endpoint
func (ae *AnalyticsEngine) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]interface{}{
		"engine":       ae.GetHealthStatus(),
		"metric_store": ae.metricStore.GetStats(),
	}

	if ae.alertManager != nil {
		stats["alerts"] = ae.alertManager.GetAlertStats()
	}

	json.NewEncoder(w).Encode(stats)
}

// handleDashboard handles the main dashboard page
func (ae *AnalyticsEngine) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	dashboardHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>eBPF HTTP Tracer - Analytics Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .metric-item { padding: 10px; border-left: 4px solid #3498db; background: #f8f9fa; }
        .metric-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .metric-label { color: #7f8c8d; font-size: 14px; }
        .status-healthy { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-error { color: #e74c3c; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
        .alert-item { padding: 10px; margin: 5px 0; border-radius: 4px; }
        .alert-firing { background: #ffebee; border-left: 4px solid #f44336; }
        .alert-resolved { background: #e8f5e8; border-left: 4px solid #4caf50; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>eBPF HTTP Tracer - Real-time Analytics Dashboard</h1>
            <p>Real-time monitoring and analytics for HTTP traffic</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        </div>

        <div class="card">
            <h2>System Health</h2>
            <div id="health-status">Loading...</div>
        </div>

        <div class="card">
            <h2>Real-time Metrics</h2>
            <div class="metrics-grid" id="metrics-grid">
                Loading metrics...
            </div>
        </div>

        <div class="card">
            <h2>Processor Statistics</h2>
            <div id="processor-stats">Loading...</div>
        </div>

        <div class="card">
            <h2>Active Alerts</h2>
            <div id="alerts-section">Loading...</div>
        </div>
    </div>

    <script>
        function refreshData() {
            loadHealth();
            loadMetrics();
            loadProcessors();
            loadAlerts();
        }

        function loadHealth() {
            fetch('/api/health')
                .then(response => response.json())
                .then(data => {
                    const healthDiv = document.getElementById('health-status');
                    const status = data.status === 'healthy' ? 'status-healthy' : 'status-error';
                    healthDiv.innerHTML = ` + "`" + `
                        <div class="${status}">
                            <strong>Status:</strong> ${data.status}<br>
                            <strong>Processors:</strong> ${data.processors}<br>
                            <strong>Aggregators:</strong> ${data.aggregators}<br>
                            <strong>Buffer Usage:</strong> ${data.buffer_size}/${data.buffer_capacity}<br>
                            <strong>Worker Threads:</strong> ${data.worker_threads}
                        </div>
                    ` + "`" + `;
                });
        }

        function loadMetrics() {
            fetch('/api/metrics?window=5m')
                .then(response => response.json())
                .then(data => {
                    const metricsDiv = document.getElementById('metrics-grid');
                    let html = '';
                    
                    if (data.current) {
                        Object.keys(data.current).forEach(key => {
                            const metric = data.current[key];
                            html += ` + "`" + `
                                <div class="metric-item">
                                    <div class="metric-value">${metric.value.toFixed(2)}</div>
                                    <div class="metric-label">${key}</div>
                                </div>
                            ` + "`" + `;
                        });
                    }
                    
                    metricsDiv.innerHTML = html || 'No metrics available';
                });
        }

        function loadProcessors() {
            fetch('/api/processors')
                .then(response => response.json())
                .then(data => {
                    const processorsDiv = document.getElementById('processor-stats');
                    let html = '';
                    
                    Object.keys(data).forEach(processor => {
                        const stats = data[processor];
                        html += ` + "`" + `
                            <div class="metric-item">
                                <strong>${processor}</strong><br>
                                Events Processed: ${stats.events_processed || 0}<br>
                                Last Processed: ${stats.last_processed || 'Never'}
                            </div>
                        ` + "`" + `;
                    });
                    
                    processorsDiv.innerHTML = html || 'No processor data available';
                });
        }

        function loadAlerts() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const alertsDiv = document.getElementById('alerts-section');
                    
                    if (!data.enabled) {
                        alertsDiv.innerHTML = '<p>Alerting is not enabled</p>';
                        return;
                    }
                    
                    let html = '';
                    
                    if (data.active_alerts && Object.keys(data.active_alerts).length > 0) {
                        Object.keys(data.active_alerts).forEach(alertName => {
                            const alert = data.active_alerts[alertName];
                            html += ` + "`" + `
                                <div class="alert-item alert-${alert.status}">
                                    <strong>${alertName}</strong> - ${alert.status}<br>
                                    Value: ${alert.value}, Started: ${alert.start_time}
                                </div>
                            ` + "`" + `;
                        });
                    } else {
                        html = '<p class="status-healthy">No active alerts</p>';
                    }
                    
                    alertsDiv.innerHTML = html;
                });
        }

        // Auto-refresh every 30 seconds
        setInterval(refreshData, 30000);
        
        // Initial load
        refreshData();
    </script>
</body>
</html>
    `

	w.Write([]byte(dashboardHTML))
}

// handleStatic handles static asset requests
func (ae *AnalyticsEngine) handleStatic(w http.ResponseWriter, r *http.Request) {
	// For now, just return 404 for static assets
	// In a real implementation, you would serve CSS, JS, and image files
	http.NotFound(w, r)
}

// PrometheusMetricsHandler returns metrics in Prometheus format
func (ae *AnalyticsEngine) PrometheusMetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		// Get current metrics
		metrics := ae.metricStore.GetCurrentMetrics()

		// Convert to Prometheus format
		for name, metric := range metrics {
			// Convert metric name to Prometheus format
			promName := convertToPrometheusName(name)
			
			// Write metric help and type
			fmt.Fprintf(w, "# HELP %s %s\n", promName, "eBPF HTTP tracer metric")
			fmt.Fprintf(w, "# TYPE %s %s\n", promName, getPrometheusType(metric.Type))
			
			// Write metric value with labels
			if len(metric.Labels) > 0 {
				labelStr := ""
				for k, v := range metric.Labels {
					if labelStr != "" {
						labelStr += ","
					}
					labelStr += fmt.Sprintf(`%s="%s"`, k, v)
				}
				fmt.Fprintf(w, "%s{%s} %f\n", promName, labelStr, metric.Value)
			} else {
				fmt.Fprintf(w, "%s %f\n", promName, metric.Value)
			}
		}
	}
}

// Helper functions

func convertToPrometheusName(name string) string {
	// Convert metric name to Prometheus naming convention
	// Replace dots and other characters with underscores
	result := ""
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' {
			result += string(char)
		} else {
			result += "_"
		}
	}
	return result
}

func getPrometheusType(metricType string) string {
	switch metricType {
	case "counter", "counter_rate":
		return "counter"
	case "histogram_percentile", "histogram_count", "histogram_average":
		return "histogram"
	default:
		return "gauge"
	}
}
