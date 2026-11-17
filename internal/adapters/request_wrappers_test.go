package adapters

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/rules"
)

func javaInventory(files map[string]string) *inventory.Inventory {
	inv := &inventory.Inventory{}
	for path, src := range files {
		inv.Files = append(inv.Files, &inventory.File{Path: path, Lang: "java", Lines: strings.Split(src, "\n")})
	}
	return inv
}

func TestRequestWrapperSources(t *testing.T) {
	inv := javaInventory(map[string]string{
		"src/main/java/com/acme/web/RequestWrapper.java": `package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class RequestWrapper {
    private HttpServletRequest request;

    public RequestWrapper(HttpServletRequest request) {
        this.request = request;
    }

    public String getTheParameter(String p) {
        return request.getParameter(p);
    }

    public String getTheCookie(String c) {
        Cookie[] cookies = this.request.getCookies();
        String value = "";
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(c)) { value = cookie.getValue(); break; }
            }
        }
        return value;
    }

    public String getTheValue(String p) {
        return "bar";
    }

    public int count() {
        return request.getContentLength();
    }
}
`,
		"src/main/java/com/acme/Util.java": `package com.acme;
public class Util {
    public String name() { return "x"; }
}
`,
		"src/test/java/com/acme/FakeRequest.java": `package com.acme;
public class FakeRequest {
    private HttpServletRequest request;
    public String p() { return request.getParameter("p"); }
}
`,
	})
	got := requestWrapperSources(inv)
	want := []string{
		"(com.acme.web.RequestWrapper $W).getTheCookie(...)",
		"(com.acme.web.RequestWrapper $W).getTheParameter(...)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if requestWrapperSources(nil) != nil {
		t.Fatal("no sources without an inventory")
	}
}

// The patterns land in the shared request sources, which every Java taint
// rule refers to.
func TestAddRequestSources(t *testing.T) {
	dir, err := rules.WriteSemgrep(filepath.Join(t.TempDir(), "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if err := addRequestSources(dir, []string{"(com.acme.W $W).get(...)"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "java.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "pattern-sources: &request\n")
	if i < 0 || !strings.HasPrefix(s[i+len("pattern-sources: &request\n"):], "      # Request wrapper classes") ||
		!strings.Contains(s, "      - pattern: (com.acme.W $W).get(...)\n") {
		t.Fatalf("sources not added:\n%s", s[:min(len(s), 1500)])
	}
	if err := addRequestSources(dir, nil); err != nil {
		t.Fatal(err)
	}
}
