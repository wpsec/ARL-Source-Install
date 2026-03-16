package dataType

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
	Target  string       `json:"target"`
	Records []ScanRecord `json:"records"`
}
