package tokens

import "hextrap.io/artifacts/internal/snapshot"

// NewFileStore returns a MemoryStore that saves a snapshot to path after
// every change, for single-node installs.
func NewFileStore(path string) (*MemoryStore, error) {
	s := NewMemoryStore()
	var records []Record
	found, err := snapshot.Load(path, &records)
	if err != nil {
		return nil, err
	}
	if found {
		for i := range records {
			s.records[records[i].ID] = &records[i]
		}
	}
	s.path = path
	return s, nil
}

// save persists the store if it's file-backed. Callers hold s.mu.
func (s *MemoryStore) save() error {
	if s.path == "" {
		return nil
	}
	records := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		records = append(records, *r)
	}
	return snapshot.Save(s.path, records)
}
