package dataType

// EndpointTriggerContext 表示接口触发上下文。
type EndpointTriggerContext struct {
	Page    string `json:"page,omitempty"`
	Event   string `json:"event,omitempty"`
	DOMHint string `json:"dom_hint,omitempty"`
}

// EndpointRequestTemplate 表示接口请求模板。
type EndpointRequestTemplate struct {
	Headers       map[string]string `json:"headers,omitempty"`
	Path          map[string]string `json:"path,omitempty"`
	Query         map[string]string `json:"query,omitempty"`
	Body          map[string]string `json:"body,omitempty"`
	QueryString   string            `json:"query_string,omitempty"`
	BodyText      string            `json:"body_text,omitempty"`
	RequestPacket string            `json:"request_packet,omitempty"`
}

// EndpointRecord 表示结构化接口结果。
type EndpointRecord struct {
	EndpointID      string                  `json:"endpoint_id"`
	Site            string                  `json:"site,omitempty"`
	PageURL         string                  `json:"page_url,omitempty"`
	URL             string                  `json:"url"`
	Path            string                  `json:"path,omitempty"`
	Method          string                  `json:"method,omitempty"`
	Protocol        string                  `json:"protocol,omitempty"`
	SourceTypes     []string                `json:"source_types,omitempty"`
	TriggerContext  EndpointTriggerContext  `json:"trigger_context,omitempty"`
	ContentType     string                  `json:"content_type,omitempty"`
	BodyKind        string                  `json:"body_kind,omitempty"`
	ResponseStatus  int                     `json:"response_status,omitempty"`
	ResponseSize    int64                   `json:"response_size,omitempty"`
	RequestTemplate EndpointRequestTemplate `json:"request_template,omitempty"`
	Confidence      float64                 `json:"confidence,omitempty"`
}

// ParameterSourceDetail 表示参数来源细节。
type ParameterSourceDetail struct {
	PageURL   string `json:"page_url,omitempty"`
	JSFile    string `json:"js_file,omitempty"`
	SchemaLib string `json:"schema_lib,omitempty"`
}

// ParameterRecord 表示结构化参数结果。
type ParameterRecord struct {
	ParameterID     string                `json:"parameter_id"`
	TaskID          string                `json:"task_id,omitempty"`
	EndpointID      string                `json:"endpoint_id"`
	ParamName       string                `json:"param_name"`
	Location        string                `json:"location,omitempty"`
	ParamType       string                `json:"param_type,omitempty"`
	Required        bool                  `json:"required,omitempty"`
	Example         string                `json:"example,omitempty"`
	Default         string                `json:"default,omitempty"`
	Enum            []string              `json:"enum,omitempty"`
	Source          string                `json:"source,omitempty"`
	SourceDetail    ParameterSourceDetail `json:"source_detail,omitempty"`
	IsPII           bool                  `json:"is_pii,omitempty"`
	Entropy         float64               `json:"entropy,omitempty"`
	Confidence      float64               `json:"confidence,omitempty"`
	OccurrenceCount int                   `json:"occurrence_count,omitempty"`
}

// ScanRecord 表示单条命中结果。
type ScanRecord struct {
	Id      string `json:"id"`
	Content string `json:"content"`
	Source  string `json:"source"`
	Tag     string `json:"tag"`
	Hash    uint64 `json:"hash"`
}

// ScanResult 表示单目标扫描输出。
type ScanResult struct {
	Target     string            `json:"target"`
	Records    []ScanRecord      `json:"records"`
	Endpoints  []EndpointRecord  `json:"endpoints,omitempty"`
	Parameters []ParameterRecord `json:"parameters,omitempty"`
}
