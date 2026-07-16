package sqlite

type Flag struct {
	Flag                string
	Exploit             string
	Status              int
	Timestamp           int64
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
