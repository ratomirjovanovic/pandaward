package py

import "testing"

func TestFiles(t *testing.T) {
	fs := NewFiles([]string{
		"web/pgadmin/__init__.py",
		"web/pgadmin/utils/__init__.py",
		"web/pgadmin/utils/paths.py",
		"web/run.py",
		"helpers/utils.py",
		"testcode/Test01.py",
	})
	for path, want := range map[string]string{
		"web/pgadmin/utils/paths.py":    "pgadmin.utils.paths",
		"web/pgadmin/utils/__init__.py": "pgadmin.utils",
		"web/run.py":                    "run",
		"helpers/utils.py":              "utils", // no __init__.py: a script directory
	} {
		if got, _ := fs.Name(path); got != want {
			t.Errorf("Name(%s) = %s, want %s", path, got, want)
		}
	}
	for name, want := range map[string]string{
		"pgadmin.utils.paths": "web/pgadmin/utils/paths.py",
		"pgadmin.utils":       "web/pgadmin/utils/__init__.py",
		"helpers.utils":       "helpers/utils.py", // by its path
		"flask":               "",
	} {
		if got := fs.Lookup(name); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", name, got, want)
		}
	}
}
