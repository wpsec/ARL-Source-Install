package scan

import (
	"math"
	"strings"

	datatype "wih/dataType"
)

var piiNameHints = []string{
	"phone",
	"mobile",
	"tel",
	"email",
	"mail",
	"idcard",
	"id_card",
	"身份证",
	"token",
	"secret",
	"access_key",
	"api_key",
	"authorization",
	"auth",
	"bearer",
	"jwt",
	"password",
	"passwd",
	"pwd",
}

func enrichParameterMetadata(record datatype.ParameterRecord) datatype.ParameterRecord {
	sampleText := firstNonEmpty(record.Example, record.Default)
	record.IsPII = inferParameterPII(record.ParamName, sampleText)
	record.Entropy = calculateStringEntropy(sampleText)
	return record
}

func inferParameterPII(paramName string, sampleText string) bool {
	merged := strings.ToLower(strings.TrimSpace(paramName + " " + sampleText))
	if merged == "" {
		return false
	}
	for _, hint := range piiNameHints {
		if strings.Contains(merged, strings.ToLower(strings.TrimSpace(hint))) {
			return true
		}
	}
	return false
}

func calculateStringEntropy(sampleText string) float64 {
	text := strings.TrimSpace(sampleText)
	if text == "" {
		return 0
	}

	runes := []rune(text)
	if len(runes) == 0 {
		return 0
	}

	countMap := make(map[rune]int)
	for _, r := range runes {
		countMap[r]++
	}

	entropy := 0.0
	total := float64(len(runes))
	for _, count := range countMap {
		probability := float64(count) / total
		entropy -= probability * math.Log2(probability)
	}
	return math.Round(entropy*1000) / 1000
}
