package resolve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlocklistMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ads.txt")
	content := `# ads
doubleclick.net
0.0.0.0 googlesyndication.com
127.0.0.1 ads.example.com
! comment
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	bl := NewBlocklist(dir)
	n, err := bl.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("count=%d want 3", n)
	}
	if !bl.Match("doubleclick.net") {
		t.Fatal("exact")
	}
	if !bl.Match("ad.doubleclick.net") {
		t.Fatal("suffix parent")
	}
	if !bl.Match("page.googlesyndication.com") {
		t.Fatal("hosts-style")
	}
	if bl.Match("example.com") {
		t.Fatal("should not match unrelated")
	}
}
