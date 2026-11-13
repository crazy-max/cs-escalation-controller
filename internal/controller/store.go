package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
)

const (
	bucketName = "controller"
	stateKey   = "state"
)

type Operation struct {
	IP                string    `json:"ip"`
	AlertID           int64     `json:"alert_id"`
	Tier              int       `json:"tier"`
	Until             time.Time `json:"until"`
	Attempted         bool      `json:"attempted"`
	SourceDecisionIDs []int64   `json:"source_decision_ids,omitempty"`
	SourceBanUntil    time.Time `json:"source_ban_until,omitzero"`
}

type State struct {
	Version  int                 `json:"version"`
	LAPI     string              `json:"lapi"`
	DryRun   bool                `json:"dry_run"`
	Started  time.Time           `json:"started"`
	Episodes map[string]Episode  `json:"episodes"`
	Seen     map[int64]time.Time `json:"seen"`
	Pending  map[int64]Operation `json:"pending"`
}

type Store struct {
	db *bolt.DB
}

func OpenStore(path, lapi string, dryRun bool, now time.Time) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout: time.Second,
	})
	if err != nil {
		return nil, err
	}

	s := &Store{
		db: db,
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		if raw := b.Get([]byte(stateKey)); raw != nil {
			var state State
			if err := json.Unmarshal(raw, &state); err != nil {
				return err
			}
			if state.Version != 1 || state.LAPI != lapi || state.DryRun != dryRun {
				return errors.New("database version, LAPI or dryRun differs; use a separate database")
			}
			return nil
		}
		state := State{
			Version:  1,
			LAPI:     lapi,
			DryRun:   dryRun,
			Started:  now,
			Episodes: map[string]Episode{},
			Seen:     map[int64]time.Time{},
			Pending:  map[int64]Operation{},
		}
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return b.Put([]byte(stateKey), data)
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Read() (State, error) {
	var state State
	err := s.db.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte(bucketName)).Get([]byte(stateKey)), &state)
	})
	return state, err
}

func (s *Store) Update(fn func(*State) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		var state State
		if err := json.Unmarshal(b.Get([]byte(stateKey)), &state); err != nil {
			return err
		}
		if err := fn(&state); err != nil {
			return err
		}
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return b.Put([]byte(stateKey), data)
	})
}
