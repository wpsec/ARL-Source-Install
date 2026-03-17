package dataType

// WIH 定义规则配置根结构。
type WIH struct {
	// 主规则（当前结构）
	Rules []Rule `yaml:"rules"`
	// 兼容历史配置：rule（单数）
	Rule []Rule `yaml:"rule"`

	// 排除规则（当前结构）
	ExcludeRules []ExcludeRule `yaml:"exclude_rules"`
	// 兼容历史配置：exclude（简写）
	Exclude []ExcludeRule `yaml:"exclude"`
}

// Rule 定义单条匹配规则。
type Rule struct {
	Id string `yaml:"id"`
	// Enabled 为空时默认启用（兼容历史未显式 enabled 的规则文件）。
	Enabled *bool `yaml:"enabled"`
	Pattern string `yaml:"pattern"`
}

// IsEnabled 返回规则是否启用。
func (r Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// ExcludeRule 定义排除规则。
// 规则逻辑：
// - 字段 id/content/target/source/source_tag 之间为 AND 关系。
// - 若字段值以 regex: 开头，则按正则匹配。
type ExcludeRule struct {
	Name      string `yaml:"name"`
	Id        string `yaml:"id"`
	Target    string `yaml:"target"`
	// Enabled 为空时默认启用，兼容历史写法。
	Enabled   *bool  `yaml:"enabled"`
	Content   string `yaml:"content"`
	Source    string `yaml:"source"`
	SourceTag string `yaml:"source_tag"`
}

// IsEnabled 返回排除规则是否启用。
func (r ExcludeRule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}
