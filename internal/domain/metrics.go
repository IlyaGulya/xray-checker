package domain

type MetricsCollector interface {
	RecordCheck(CheckResult)
	RecordWorkerStart(workerID string)
	RecordWorkerStop(workerID string)
	RecordSchedulerJob(linkName string)
	RecordCheckRetry(linkName string)
	RecordXrayRestart()
}
