/*
Package fingerprint - Similarity Scoring Module

Calculates similarity between fingerprints to detect coordinated attacks
and IP rotation campaigns.
*/
package fingerprint

import (
	"math"
)

// CalculateSimilarity compares two fingerprints and returns a similarity score (0.0 - 1.0)
func CalculateSimilarity(fp1, fp2 *Fingerprint) float64 {
	if fp1 == nil || fp2 == nil {
		return 0.0
	}

	// Weighted similarity components
	headerSim := calculateHeaderSimilarity(fp1, fp2) * 0.4
	uaSim := calculateUserAgentSimilarity(fp1, fp2) * 0.3
	ipSim := calculateIPClusterSimilarity(fp1, fp2) * 0.2
	timingSim := calculateTimingSimilarity(fp1, fp2) * 0.1

	return headerSim + uaSim + ipSim + timingSim
}

// calculateHeaderSimilarity uses Jaccard similarity for header shapes
func calculateHeaderSimilarity(fp1, fp2 *Fingerprint) float64 {
	// Extract header order (header shape)
	headers1 := fp1.Components["header_order"]
	headers2 := fp2.Components["header_order"]

	if headers1 == "" || headers2 == "" {
		return 0.0
	}

	// Simple Jaccard index
	return jaccardSimilarity(headers1, headers2)
}

// calculateUserAgentSimilarity compares User-Agent strings
func calculateUserAgentSimilarity(fp1, fp2 *Fingerprint) float64 {
	ua1 := fp1.Components["User-Agent"]
	ua2 := fp2.Components["User-Agent"]

	if ua1 == "" || ua2 == "" {
		return 0.0
	}

	// Exact match
	if ua1 == ua2 {
		return 1.0
	}

	// Partial match (same browser family)
	if hasSameBrowserFamily(ua1, ua2) {
		return 0.7
	}

	return 0.0
}

// calculateIPClusterSimilarity checks for overlapping IP ranges
func calculateIPClusterSimilarity(fp1, fp2 *Fingerprint) float64 {
	if len(fp1.IPs) == 0 || len(fp2.IPs) == 0 {
		return 0.0
	}

	// Count shared IPs
	shared := 0
	for _, ip1 := range fp1.IPs {
		for _, ip2 := range fp2.IPs {
			if ip1 == ip2 {
				shared++
				break
			}
		}
	}

	// Jaccard similarity for IP sets
	total := len(fp1.IPs) + len(fp2.IPs) - shared
	if total == 0 {
		return 0.0
	}

	return float64(shared) / float64(total)
}

// calculateTimingSimilarity compares timing patterns (placeholder)
func calculateTimingSimilarity(fp1, fp2 *Fingerprint) float64 {
	// This would compare timing patterns if available
	// For now, return neutral score
	return 0.5
}

// jaccardSimilarity calculates Jaccard similarity between two comma-separated strings
func jaccardSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Convert to sets
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, item := range splitAndTrim(s1, ",") {
		set1[item] = true
	}
	for _, item := range splitAndTrim(s2, ",") {
		set2[item] = true
	}

	// Calculate intersection and union
	intersection := 0
	for item := range set1 {
		if set2[item] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// hasSameBrowserFamily checks if two user agents are from the same browser family
func hasSameBrowserFamily(ua1, ua2 string) bool {
	browsers := []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}

	for _, browser := range browsers {
		if contains([]string{ua1}, browser) && contains([]string{ua2}, browser) {
			return true
		}
	}

	return false
}

// splitAndTrim splits a string and trims whitespace
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := []string{}
	current := ""

	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			if current != "" {
				parts = append(parts, trimSpace(current))
			}
			current = ""
		} else {
			current += string(s[i])
		}
	}

	if current != "" {
		parts = append(parts, trimSpace(current))
	}

	return parts
}

// trimSpace removes leading/trailing whitespace
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

// FingerprintCluster represents a group of similar fingerprints
type FingerprintCluster struct {
	Fingerprints []*Fingerprint
	AvgSimilarity float64
	ThreatLevel   float64
}

// FindSimilarFingerprints finds fingerprints similar to the given one
func FindSimilarFingerprints(target *Fingerprint, candidates []*Fingerprint, threshold float64) []*Fingerprint {
	similar := []*Fingerprint{}

	for _, candidate := range candidates {
		if candidate.Hash == target.Hash {
			continue // Skip self
		}

		similarity := CalculateSimilarity(target, candidate)
		if similarity >= threshold {
			similar = append(similar, candidate)
		}
	}

	return similar
}

// ClusterFingerprints groups fingerprints by similarity
func ClusterFingerprints(fingerprints []*Fingerprint, threshold float64) []*FingerprintCluster {
	clusters := []*FingerprintCluster{}
	processed := make(map[string]bool)

	for _, fp := range fingerprints {
		if processed[fp.Hash] {
			continue
		}

		// Find all similar fingerprints
		similar := FindSimilarFingerprints(fp, fingerprints, threshold)

		if len(similar) > 0 {
			cluster := &FingerprintCluster{
				Fingerprints: append([]*Fingerprint{fp}, similar...),
			}

			// Calculate average similarity
			totalSim := 0.0
			count := 0
			for i, fp1 := range cluster.Fingerprints {
				for j := i + 1; j < len(cluster.Fingerprints); j++ {
					totalSim += CalculateSimilarity(fp1, cluster.Fingerprints[j])
					count++
				}
			}

			if count > 0 {
				cluster.AvgSimilarity = totalSim / float64(count)
			}

			// Calculate threat level (clusters = coordinated attack)
			cluster.ThreatLevel = math.Min(float64(len(cluster.Fingerprints))*0.1+cluster.AvgSimilarity*0.5, 1.0)

			clusters = append(clusters, cluster)

			// Mark as processed
			processed[fp.Hash] = true
			for _, similar := range similar {
				processed[similar.Hash] = true
			}
		}
	}

	return clusters
}
