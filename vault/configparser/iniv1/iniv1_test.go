package iniv1

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	return path
}

// TestLoadConcurrentNoRace verifies that concurrent Load() calls on distinct
// Parser instances do not race on shared state.  Run with -race to detect the
// data race on ini.PrettyFormat that exists before the sync.Once fix.
func TestLoadConcurrentNoRace(t *testing.T) {
	path := writeConfig(t, "[profile foo]\nregion=us-east-1\n")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := New()
			if err := p.Load(path); err != nil {
				t.Errorf("Load: %v", err)
			}
		}()
	}
	wg.Wait()
}
