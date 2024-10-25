package domain

import (
	"time"
)

type Check struct {
	Link      ParsedLink
	Status    string
	SourceIP  string
	VPNIP     string
	Error     error
	TimeStamp time.Time
}

type CheckResult struct {
	Check     Check
	Duration  time.Duration
	Completed time.Time
}
