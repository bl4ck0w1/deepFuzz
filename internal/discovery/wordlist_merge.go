package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type MergeSpec struct {
	Sources []string 
	Dest    string   
	Filter  func(string) bool 
}

func NormalizePath(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") { return "", false }

	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if i := strings.Index(s[8:], "/"); i >= 0 {
			s = s[strings.Index(s, "/"):]
		} else {
			return "", false
		}
	}

	s = strings.ReplaceAll(s, "\\", "/")

	if !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "?") {
		s = "/" + s
	}

	reg := regexp.MustCompile(`/+`)
	s = reg.ReplaceAllString(s, `/`)

	if len(s) > 256 { return "", false }

	return s, true
}

func MergeWordlists(root string, specs []MergeSpec) error {
	for _, spec := range specs {
		set := make(map[string]struct{})
		for _, g := range spec.Sources {
			matches, _ := filepath.Glob(filepath.Join(root, "upstream", g))
			for _, f := range matches {
				fd, err := os.Open(f); if err != nil { continue }
				sc := bufio.NewScanner(fd)
				sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
				for sc.Scan() {
					line := sc.Text()
					if spec.Filter != nil && !spec.Filter(line) { continue }
					if n, ok := NormalizePath(line); ok {
						set[n] = struct{}{}
					}
				}
				fd.Close()
			}
		}
		
		out := make([]string, 0, len(set))
		for k := range set { out = append(out, k) }
		sort.Strings(out)

		dest := filepath.Join(root, spec.Dest)
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		tmp := dest + ".tmp"
		if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil { return err }
		if err := os.Rename(tmp, dest); err != nil { return err }
	}
	return nil
}
