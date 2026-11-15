package flow

import (
	"sort"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/java"
)

// javaProject analyzes Java files together, with properties, and returns
// "file:sink:line" for each flow.
func javaProject(t *testing.T, files map[string]string, props map[string]string) []string {
	t.Helper()
	spec, err := taint.Load("java")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	idx := java.NewFiles(paths)
	mods := map[string][]*ir.Module{}
	load := func(p string) []*ir.Module {
		if m, ok := mods[p]; ok {
			return m
		}
		f := java.Parse(p, files[p])
		if len(f.Errors) > 0 {
			t.Fatalf("%s: %v", p, f.Errors)
		}
		mods[p] = java.LowerWith(f, spec.Classes())
		return mods[p]
	}
	proj := New(spec).NewProject(func(name string) (*ir.Module, []string) {
		p := idx.Lookup(name)
		for _, m := range load(p) {
			if m.Name == name {
				return m, strings.Split(files[p], "\n")
			}
		}
		return nil, nil
	})
	proj.SetProperties(props)
	var out []string
	for _, p := range paths {
		for _, m := range load(p) {
			for _, fd := range proj.Module(m.Name) {
				out = append(out, fd.File+":"+strings.TrimPrefix(fd.Sink.ID, "taint.java-")+":"+itoa(fd.Line))
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestJavaServlet(t *testing.T) {
	files := map[string]string{
		"src/main/java/app/Wrapper.java": `package app;
import javax.servlet.http.HttpServletRequest;
public class Wrapper {
    private HttpServletRequest request;
    public Wrapper(HttpServletRequest request) { this.request = request; }
    public String get(String name) { return request.getParameter(name); }
    public String safe(String name) { return "constant"; }
}
`,
		"src/main/java/app/Page.java": `package app;
import javax.servlet.http.*;
import java.util.*;
public class Page extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Wrapper w = new Wrapper(request);
        String p = w.get("p");
        String s = w.safe("s");
        java.sql.Statement st = conn().createStatement();
        st.executeQuery("SELECT * FROM t WHERE a = '" + p + "'");
        st.executeQuery("SELECT * FROM t WHERE a = '" + s + "'");
        java.sql.PreparedStatement ps = conn().prepareStatement("SELECT * FROM t WHERE a = ?");
        ps.setString(1, p);
        List<String> l = new ArrayList<String>();
        l.add("safe");
        l.add(p);
        l.remove(0);
        response.getWriter().println(l.get(0));
        response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(p));
        String guess = "ABC";
        String bar;
        switch (guess.charAt(1)) {
            case 'A': bar = p; break;
            case 'B': bar = "bob"; break;
            default: bar = p;
        }
        Runtime.getRuntime().exec("echo " + bar);
        new java.io.File("/data", p);
        request.getSession().setAttribute("user", p);
        java.io.PrintWriter log = new java.io.PrintWriter("app.log");
        log.println(p);
    }
    java.sql.Connection conn() { return null; }
}
`,
	}
	got := strings.Join(javaProject(t, files, nil), " ")
	want := strings.Join([]string{
		"src/main/java/app/Page.java:path-traversal:28",
		"src/main/java/app/Page.java:sql-injection:10",
		"src/main/java/app/Page.java:trust-boundary:29",
		"src/main/java/app/Page.java:xss:18",
	}, " ")
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// Weak algorithms, also read from a properties file; predictable numbers
// in a cookie; cookies without Secure; Spring parameters as sources.
func TestJavaWeakAndSpring(t *testing.T) {
	files := map[string]string{
		"src/main/java/app/C.java": `package app;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.RequestParam;
public class C {
    void f(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.util.Properties props = new java.util.Properties();
        java.security.MessageDigest.getInstance(props.getProperty("hashAlg1", "SHA-256"));
        java.security.MessageDigest.getInstance(props.getProperty("hashAlg2", "MD5"));
        javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.KeyGenerator.getInstance("AES");
        String v = Float.toString(new java.util.Random().nextFloat());
        response.addCookie(new Cookie("rememberMe" + v.length(), v));
        String w = Long.toString(new java.security.SecureRandom().nextLong());
        response.addCookie(new Cookie("rememberMe", w));
        Cookie c = new Cookie("x", "y");
        c.setSecure(false);
        c.setSecure(true);
    }
    public String g(@RequestParam("q") String q, @RequestParam("n") int n) throws Exception {
        Runtime.getRuntime().exec(q);
        Runtime.getRuntime().exec("ls " + n);
        return q;
    }
}
`,
	}
	got := strings.Join(javaProject(t, files, map[string]string{"hashAlg1": "MD5", "hashAlg2": "SHA-512"}), " ")
	want := strings.Join([]string{
		"src/main/java/app/C.java:command-injection:21",
		"src/main/java/app/C.java:insecure-cookie:17",
		"src/main/java/app/C.java:weak-crypto:9",
		"src/main/java/app/C.java:weak-hash:7",
		"src/main/java/app/C.java:weak-random:13",
	}, " ")
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
