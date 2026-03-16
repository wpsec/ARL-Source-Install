package dataType

// WIH 定义规则配置根结构。
type WIH struct {
	Rules        []Rule        `yaml:"rules"`
	ExcludeRules []ExcludeRule `yaml:"exclude_rules"`
}

// Rule 定义单条匹配规则。
type Rule struct {
	Id      string `yaml:"id"`
	Enabled bool   `yaml:"enabled"`
	Pattern string `yaml:"pattern"`
}

// ExcludeRule 定义排除规则。
// 规则逻辑：
// - 字段 id/content/target/source/source_tag 之间为 AND 关系。
// - 若字段值以 regex: 开头，则按正则匹配。
type ExcludeRule struct {
	Name      string `yaml:"name"`
	Id        string `yaml:"id"`
	Target    string `yaml:"target"`
	Enabled   bool   `yaml:"enabled"`
	Content   string `yaml:"content"`
	Source    string `yaml:"source"`
	SourceTag string `yaml:"source_tag"`
}
