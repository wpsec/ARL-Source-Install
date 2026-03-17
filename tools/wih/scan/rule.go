package scan

import (
	"fmt"
	"os"
	"strings"
	datatype "wih/dataType"
	"wih/global"
	"wih/util"

	"gopkg.in/yaml.v3"
)

// builtinPatterns 提供内置规则的默认正则。
var builtinPatterns = map[string]string{
	"domain":     `\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b`,
	"ip":         `\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`,
	"path":       `/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]{1,80}/?){1,8}`,
	"domain_url": `https?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::\d{1,5})?(?:/[^\s"'<>]*)?`,
	"ip_url":     `https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s"'<>]*)?`,
	"secret_key": `(?i)(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*["'][^"'\\\s]{8,}["']`,
}

// rule 对响应体执行规则匹配并返回去重后的记录。
func rule(body string, target string, sourceTag string) []datatype.ScanRecord {
	if global.RuleWIH == nil || len(global.RuleWIH.Rules) == 0 || strings.TrimSpace(body) == "" {
		return nil
	}

	resultList := make([]datatype.ScanRecord, 0)
	hashSet := make(map[uint64]struct{})

	for _, ruleItem := range global.RuleWIH.Rules {
		if !ruleItem.IsEnabled() {
			continue
		}

		pattern := resolvePattern(ruleItem)
		if pattern == "" {
			continue
		}

		remaining := global.MaxCollect - len(resultList)
		if remaining <= 0 {
			break
		}

		matches, err := util.Regex2Limit(body, pattern, remaining)
		if err != nil || len(matches) == 0 {
			continue
		}

		for _, content := range matches {
			record := datatype.ScanRecord{
				Id:      ruleItem.Id,
				Content: content,
				Source:  target,
				Tag:     "",
			}

			if isExcluded(record, target, sourceTag) {
				continue
			}

			hashText := ruleItem.Id + "|" + content + "|" + target + "|" + sourceTag
			record.Hash = util.StableHash(hashText)
			if _, exists := hashSet[record.Hash]; exists {
				continue
			}
			hashSet[record.Hash] = struct{}{}
			resultList = append(resultList, record)

			if len(resultList) >= global.MaxCollect {
				break
			}
		}
	}

	return resultList
}

// resolvePattern 返回规则实际使用的正则表达式。
func resolvePattern(item datatype.Rule) string {
	pattern := strings.TrimSpace(item.Pattern)
	if pattern != "" {
		return pattern
	}
	return builtinPatterns[strings.ToLower(strings.TrimSpace(item.Id))]
}

// isExcluded 判断记录是否命中排除规则。
func isExcluded(record datatype.ScanRecord, target string, sourceTag string) bool {
	if global.RuleWIH == nil || len(global.RuleWIH.ExcludeRules) == 0 {
		return false
	}

	for _, excludeRule := range global.RuleWIH.ExcludeRules {
		if !excludeRule.IsEnabled() {
			continue
		}
		if !matchExcludeField(excludeRule.Id, record.Id) {
			continue
		}
		if !matchExcludeField(excludeRule.Content, record.Content) {
			continue
		}
		if !matchExcludeField(excludeRule.Target, target) {
			continue
		}
		if !matchExcludeField(excludeRule.Source, record.Source) {
			continue
		}
		if !matchExcludeField(excludeRule.SourceTag, sourceTag) {
			continue
		}
		return true
	}

	return false
}

// matchExcludeField 判断排除字段是否匹配。
func matchExcludeField(ruleValue string, inputValue string) bool {
	ruleValue = strings.TrimSpace(ruleValue)
	if ruleValue == "" {
		return true
	}

	if strings.HasPrefix(ruleValue, "regex:") {
		pattern := strings.TrimSpace(strings.TrimPrefix(ruleValue, "regex:"))
		if pattern == "" {
			return true
		}
		results, err := util.Regex2Limit(inputValue, pattern, 1)
		if err != nil {
			return false
		}
		return len(results) > 0
	}

	return strings.TrimSpace(inputValue) == ruleValue
}

// RuleLoad 加载规则文件到全局配置。
func RuleLoad() {
	config, err := loadRuleConfig(global.RulePath)
	if err == nil {
		global.RuleWIH = config
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "[wih] load rule file failed path=%s err=%v, fallback embedded template\n", global.RulePath, err)
	embedded := util.ReadEmbeddedRuleTemplate()
	if len(embedded) > 0 {
		embeddedConfig := &datatype.WIH{}
		if unmarshalErr := yaml.Unmarshal(embedded, embeddedConfig); unmarshalErr == nil {
			normalizeCompatConfig(embeddedConfig)
			if len(embeddedConfig.Rules) > 0 {
				global.RuleWIH = embeddedConfig
				return
			}
		}
	}

	// 最终兜底：启用最小内置规则，避免“静默空结果”。
	global.RuleWIH = &datatype.WIH{
		Rules: []datatype.Rule{
			{Id: "domain"},
			{Id: "ip"},
			{Id: "path"},
			{Id: "domain_url"},
			{Id: "ip_url"},
			{Id: "secret_key"},
		},
	}
	_, _ = fmt.Fprintln(os.Stderr, "[wih] fallback to minimal builtin rules")
}

func loadRuleConfig(path string) (*datatype.WIH, error) {
	content := util.ReadFile2Byte(path)
	if len(content) == 0 {
		return nil, fmt.Errorf("empty rule file")
	}

	config := &datatype.WIH{}
	if err := yaml.Unmarshal(content, config); err != nil {
		return nil, err
	}
	normalizeCompatConfig(config)
	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("no rules loaded")
	}
	return config, nil
}

func normalizeCompatConfig(config *datatype.WIH) {
	if config == nil {
		return
	}

	// 兼容旧结构：rule -> rules
	if len(config.Rules) == 0 && len(config.Rule) > 0 {
		config.Rules = config.Rule
	}
	// 兼容旧结构：exclude -> exclude_rules
	if len(config.ExcludeRules) == 0 && len(config.Exclude) > 0 {
		config.ExcludeRules = config.Exclude
	}
}
