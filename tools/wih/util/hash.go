package util

import "hash/fnv"

// StableHash 使用 FNV-1a 生成稳定哈希，用于去重。
func StableHash(text string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	return h.Sum64()
}
