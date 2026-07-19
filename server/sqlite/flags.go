package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/havce/H4ppyFarm/log"
)

type FlagService struct {
	db *DB

	batchLimit   int
	flagLifeTime int64
}

func NewFlagService(db *DB, batchLimit int, flagLifeTime int64) *FlagService {
	return &FlagService{db: db, batchLimit: batchLimit, flagLifeTime: flagLifeTime}
}

func (db *DB) CreateSchema() error {
	_, err := db.db.Exec(`
		CREATE TABLE IF NOT EXISTS flags (
			flag TEXT PRIMARY KEY,
			exploit TEXT NOT NULL,
			status INTEGER NOT NULL,
			timestamp INTEGER NOT NULL,
			submission_timestamp INTEGER,
			system_message TEXT
		);
	`)
	return err
}

func timeToDate(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:00")
}

func (s *FlagService) MarkExpired(ctx context.Context) error {
	now := time.Now().Unix()
	expire_threshold := now - s.flagLifeTime

	log.Info("Expiring all flags older than ", timeToDate(expire_threshold))
	_, err := s.db.db.ExecContext(
		ctx,
		`UPDATE flags
		    SET status = ?
		  WHERE status = ? and timestamp <= ?`,
		statusMap["EXPIRED"],
		statusMap["PENDING"],
		expire_threshold,
	)

	return err
}

func (s *FlagService) Create(ctx context.Context, f *Flag) error {
	_, err := s.db.db.ExecContext(
		ctx,
		`INSERT INTO flags
		 (flag, exploit, status, timestamp, submission_timestamp, system_message)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(flag) DO NOTHING`,
		f.Flag,
		f.Exploit,
		f.Status,
		f.Timestamp,
		f.SubmissionTimestamp,
		f.SystemMessage,
	)
	return err
}

func (s *FlagService) Get(ctx context.Context, flag string) (*Flag, error) {
	var f Flag

	err := s.db.db.QueryRowContext(
		ctx,
		`SELECT flag, exploit, status, timestamp,
		        submission_timestamp, system_message
		   FROM flags
		  WHERE flag = ?`,
		flag,
	).Scan(
		&f.Flag,
		&f.Exploit,
		&f.Status,
		&f.Timestamp,
		&f.SubmissionTimestamp,
		&f.SystemMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &f, nil
}

func (s *FlagService) GetPending(ctx context.Context) ([]Flag, error) {
	rows, err := s.db.db.QueryContext(
		ctx,
		`SELECT flag, exploit, status, timestamp,
		        submission_timestamp, system_message
		   FROM flags
		  WHERE status = ?
		  LIMIT ?`,
		statusMap["PENDING"],
		s.batchLimit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Flag
	for rows.Next() {
		var f Flag
		if err := rows.Scan(
			&f.Flag,
			&f.Exploit,
			&f.Status,
			&f.Timestamp,
			&f.SubmissionTimestamp,
			&f.SystemMessage,
		); err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	return out, rows.Err()
}

func (s *FlagService) GetFlags(ctx context.Context, offset int, count int) ([]Flag, error) {
	rows, err := s.db.db.QueryContext(
		ctx,
		`SELECT flag, exploit, status, timestamp,
		        submission_timestamp, system_message
		  FROM flags
		  ORDER BY timestamp DESC
		  LIMIT ?
		  OFFSET ?`,
		count,
		offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Flag
	for rows.Next() {
		var f Flag
		if err := rows.Scan(
			&f.Flag,
			&f.Exploit,
			&f.Status,
			&f.Timestamp,
			&f.SubmissionTimestamp,
			&f.SystemMessage,
		); err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	return out, rows.Err()
}

func (s *FlagService) UpdateResult(ctx context.Context, f *Flag) error {
	_, err := s.db.db.ExecContext(
		ctx,
		`UPDATE flags
		    SET status = ?,
		        submission_timestamp = ?,
		        system_message = ?
		  WHERE flag = ?`,
		f.Status,
		f.SubmissionTimestamp,
		f.SystemMessage,
		f.Flag,
	)
	return err
}
