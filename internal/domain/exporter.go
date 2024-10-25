package domain

type Exporter interface {
	Export(check Check) error
}
