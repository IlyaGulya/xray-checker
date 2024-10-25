package domain

type LinkName string

type RawLink struct {
	Name LinkName `json:"name"`
	URL  string   `json:"url"`
}

type ParsedLink struct {
	LinkName    LinkName
	Protocol    string
	UID         string
	Server      string
	Port        string
	Security    string
	Type        string
	HeaderType  string
	Flow        string
	Path        string
	Host        string
	SNI         string
	FP          string
	PBK         string
	SID         string
	Name        string
	Method      string
	ProxyConfig ProxyConfig
}

type ProxyConfig struct {
	ListenAddress string
	ListenPort    int
	ConfigPath    string
}
