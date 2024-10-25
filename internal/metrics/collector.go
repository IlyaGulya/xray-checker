package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"xray-checker/internal/domain"
)

// Module provides the metrics collector
var Module = fx.Options(
	fx.Provide(NewCollector),
	fx.Provide(func(c *Collector) domain.MetricsCollector { return c }),
)

type Collector struct {
	logger          *zap.Logger
	checksTotal     *prometheus.CounterVec
	checksDuration  *prometheus.HistogramVec
	lastCheckStatus *prometheus.GaugeVec
	workerStarts    *prometheus.CounterVec
	workerStops     *prometheus.CounterVec
	activeWorkers   prometheus.Gauge
	jobsScheduled   *prometheus.CounterVec
	checkErrors     *prometheus.CounterVec
	checkRetries    *prometheus.CounterVec
	xrayRestarts    prometheus.Counter
}

func NewCollector(logger *zap.Logger) *Collector {
	return &Collector{
		logger: logger,
		checksTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_checks_total",
				Help: "Total number of VPN checks performed",
			},
			[]string{"status", "link_name"},
		),
		checksDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "xray_check_duration_seconds",
				Help:    "Duration of VPN checks",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"link_name"},
		),
		lastCheckStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "xray_check_status",
				Help: "Latest check status (1 for success, 0 for failure)",
			},
			[]string{"link_name"},
		),
		workerStarts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_worker_starts_total",
				Help: "Total number of worker starts",
			},
			[]string{"worker_id"},
		),
		workerStops: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_worker_stops_total",
				Help: "Total number of worker stops",
			},
			[]string{"worker_id"},
		),
		activeWorkers: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "xray_active_workers",
				Help: "Number of currently active workers",
			},
		),
		jobsScheduled: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_jobs_scheduled_total",
				Help: "Total number of jobs scheduled",
			},
			[]string{"link_name"},
		),
		checkErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_check_errors_total",
				Help: "Total number of check errors",
			},
			[]string{"link_name", "error_type"},
		),
		checkRetries: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "xray_check_retries_total",
				Help: "Total number of check retries",
			},
			[]string{"link_name"},
		),
		xrayRestarts: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "xray_process_restarts_total",
				Help: "Total number of Xray process restarts",
			},
		),
	}
}

func (c *Collector) RecordCheck(result domain.CheckResult) {
	linkName := string(result.Check.Link.LinkName)
	c.checksTotal.WithLabelValues(result.Check.Status, linkName).Inc()
	c.checksDuration.WithLabelValues(linkName).Observe(result.Duration.Seconds())

	status := 0.0
	if result.Check.Status == "Success" {
		status = 1.0
	}
	c.lastCheckStatus.WithLabelValues(linkName).Set(status)
}

func (c *Collector) RecordWorkerStart(workerID string) {
	c.workerStarts.WithLabelValues(workerID).Inc()
	c.activeWorkers.Inc()
}

func (c *Collector) RecordWorkerStop(workerID string) {
	c.workerStops.WithLabelValues(workerID).Inc()
	c.activeWorkers.Dec()
}

func (c *Collector) RecordSchedulerJob(linkName string) {
	c.jobsScheduled.WithLabelValues(linkName).Inc()
}

func (c *Collector) RecordCheckRetry(linkName string) {
	c.checkRetries.WithLabelValues(linkName).Inc()
}

func (c *Collector) RecordXrayRestart() {
	c.xrayRestarts.Inc()
}
