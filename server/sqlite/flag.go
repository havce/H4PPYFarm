package sqlite

type Flag struct {
	Flag                string
	Exploit             string
	Status              int
	Timestamp           float64
	SubmissionTimestamp *int64
	SystemMessage       *string
}

var statusMap = map[string]int{
	"PENDING":  0,
	"EXPIRED":  1,
	"UNKNOWN":  2,
	"ACCEPTED": 3,
	"DENIED":   4,
	"RESUBMIT": 4,
	"ERROR":    4,
}

// StatusFromString maps a ForcAD status string (e.g. "ACCEPTED",
// "DENIED", "RESUBMIT", "ERROR", "UNKNOWN") to its internal integer
// status. Unrecognized values fall back to UNKNOWN.
func StatusFromString(status string) int {
	if v, ok := statusMap[status]; ok {
		return v
	}
	return statusMap["UNKNOWN"]
}
