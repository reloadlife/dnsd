package resolve

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Blocklist is an in-memory domain set for O(1) exact + suffix walks.
// Used for large ad/malware lists without one DnsRule per domain.
type Blocklist struct {
	mu   sync.RWMutex
	set  map[string]struct{}
	dirs []string
	// sources lists file paths last loaded
	sources []string
	count   int
}

// NewBlocklist creates an empty blocklist watching the given directories.
func NewBlocklist(dirs ...string) *Blocklist {
	b := &Blocklist{set: make(map[string]struct{}), dirs: dirs}
	return b
}

// Count returns loaded domain count.
func (b *Blocklist) Count() int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// Sources returns last-loaded file paths.
func (b *Blocklist) Sources() []string {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, len(b.sources))
	copy(out, b.sources)
	return out
}

// Match reports whether name (no trailing dot) is blocked exactly or by parent suffix.
func (b *Blocklist) Match(name string) bool {
	if b == nil {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.set) == 0 {
		return false
	}
	// exact + every parent: ads.foo.bar → bar, foo.bar, ads.foo.bar
	for {
		if _, ok := b.set[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

// Reload reads all *.txt / *.list / hosts-style files from configured dirs.
// Lines: bare domains, "0.0.0.0 domain", "127.0.0.1 domain", comments with #.
func (b *Blocklist) Reload() (int, error) {
	if b == nil {
		return 0, fmt.Errorf("nil blocklist")
	}
	next := make(map[string]struct{}, 65536)
	var sources []string
	for _, dir := range b.dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			low := strings.ToLower(name)
			if !strings.HasSuffix(low, ".txt") &&
				!strings.HasSuffix(low, ".list") &&
				!strings.HasSuffix(low, ".hosts") &&
				name != "hosts" {
				continue
			}
			path := filepath.Join(dir, name)
			n, err := loadBlocklistFile(path, next)
			if err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
			if n > 0 {
				sources = append(sources, path)
			}
		}
	}
	b.mu.Lock()
	b.set = next
	b.count = len(next)
	b.sources = sources
	b.mu.Unlock()
	return len(next), nil
}

func loadBlocklistFile(path string, into map[string]struct{}) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// large lines rare in hosts files
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	added := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// strip inline comments
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		var domain string
		switch len(fields) {
		case 1:
			domain = fields[0]
		default:
			// hosts: 0.0.0.0 domain [aliases…]
			if isIPToken(fields[0]) {
				domain = fields[1]
			} else {
				domain = fields[0]
			}
		}
		domain = normalizeDomain(domain)
		if domain == "" || !isPlausibleDomain(domain) {
			continue
		}
		if _, ok := into[domain]; !ok {
			into[domain] = struct{}{}
			added++
		}
	}
	return added, sc.Err()
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	// reject URLs
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/\\") {
		return ""
	}
	return s
}

func isIPToken(s string) bool {
	// rough: digits/colons/dots only → IP-ish
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' || r == ':' || r == 'a' || r == 'b' || r == 'c' || r == 'd' || r == 'e' || r == 'f' || r == 'A' || r == 'B' || r == 'C' || r == 'D' || r == 'E' || r == 'F' {
			continue
		}
		return false
	}
	return strings.ContainsAny(s, ".:")
}

func isPlausibleDomain(s string) bool {
	if len(s) < 2 || len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false // skip bare labels like "localhost"
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			continue
		}
		return false
	}
	return true
}
