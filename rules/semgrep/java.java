import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.xpath.XPath;
import org.apache.commons.io.FilenameUtils;
import org.owasp.esapi.ESAPI;
import org.springframework.jdbc.core.JdbcTemplate;

public class Fixture {
    void lookup(HttpServletRequest request, Connection conn, JdbcTemplate jdbc) throws Exception {
        String id = request.getParameter("id");
        Statement st = conn.createStatement();
        // ruleid: pandaward-java-sql-injection
        st.executeQuery("SELECT * FROM invoices WHERE id = " + id);
        // ruleid: pandaward-java-sql-injection
        jdbc.queryForList("SELECT * FROM invoices WHERE owner = '" + id + "'");
        // ok: pandaward-java-sql-injection
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM invoices WHERE id = ?");
        ps.setString(1, id);
        // ok: pandaward-java-sql-injection
        st.executeQuery("SELECT * FROM invoices WHERE id = " + 42);
    }

    void run(HttpServletRequest request) throws Exception {
        String dir = request.getHeader("X-Dir");
        // ruleid: pandaward-java-command-exec
        Runtime.getRuntime().exec("ls " + dir);
        Runtime r = Runtime.getRuntime();
        // ruleid: pandaward-java-command-exec
        r.exec(new String[] {"ls"}, new String[] {"DIR=" + dir});
        // ruleid: pandaward-java-command-exec
        new ProcessBuilder("sh", "-c", "ls " + dir).start();
        // ok: pandaward-java-command-exec
        Runtime.getRuntime().exec("ls -la");
        // ok: pandaward-java-command-exec
        new ProcessBuilder("ls", "/srv").start();
    }

    void files(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // ruleid: pandaward-java-path-traversal
        FileInputStream in = new FileInputStream(name);
        // ruleid: pandaward-java-path-traversal
        File f = new java.io.File("/srv/files", name);
        // ok: pandaward-java-path-traversal
        File safe = new File("/srv/files", FilenameUtils.getName(name));
        // ok: pandaward-java-path-traversal
        File fixed = new File("/srv/files", "index.txt");
    }

    void ldap(HttpServletRequest request, DirContext ctx) throws Exception {
        String user = request.getParameter("user");
        SearchControls sc = new SearchControls();
        // ruleid: pandaward-java-ldap-injection
        ctx.search("ou=users", "(uid=" + user + ")", sc);
        // ok: pandaward-java-ldap-injection
        ctx.search("ou=users", "(uid=" + ESAPI.encoder().encodeForLDAP(user) + ")", sc);
        // ok: pandaward-java-ldap-injection
        ctx.search("ou=users", "(uid={0})", new Object[] {user}, sc);
    }

    void xpath(HttpServletRequest request, XPath xp, org.w3c.dom.Document doc) throws Exception {
        String id = request.getParameter("id");
        // ruleid: pandaward-java-xpath-injection
        xp.evaluate("/users/user[@id='" + id + "']", doc);
        // ok: pandaward-java-xpath-injection
        xp.evaluate("/users/user[@id='" + ESAPI.encoder().encodeForXPath(id) + "']", doc);
    }

    void page(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        // ruleid: pandaward-java-xss
        response.getWriter().println("Results for " + q);
        PrintWriter out = response.getWriter();
        // ruleid: pandaward-java-xss
        out.format(java.util.Locale.US, "Results for %s", q);
        // ok: pandaward-java-xss
        out.println("Results for " + ESAPI.encoder().encodeForHTML(q));
        // ok: pandaward-java-xss
        out.println("No results");
    }

    void session(HttpServletRequest request) throws Exception {
        String role = request.getParameter("role");
        HttpSession s = request.getSession();
        // ruleid: pandaward-java-trust-boundary
        s.setAttribute("role", role);
        // ruleid: pandaward-java-trust-boundary
        request.getSession().putValue(role, "x");
        // ok: pandaward-java-trust-boundary
        s.setAttribute("visited", Boolean.TRUE);
    }

    void proxy(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        // ruleid: pandaward-java-ssrf
        URL u = new URL(target);
        // ok: pandaward-java-ssrf
        URL s = new URL("https://api.example.org/status");
    }

    Object load(InputStream in) throws Exception {
        // ruleid: pandaward-java-deserialization
        return new ObjectInputStream(in).readObject();
    }

    Object loadJson(InputStream in) throws Exception {
        // ok: pandaward-java-deserialization
        return new com.fasterxml.jackson.databind.ObjectMapper().readValue(in, Object.class);
    }

    void crypto() throws Exception {
        // ruleid: pandaward-java-weak-cipher
        Cipher a = Cipher.getInstance("DES");
        // ruleid: pandaward-java-weak-cipher
        Cipher b = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: pandaward-java-weak-cipher
        Cipher c = javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ruleid: pandaward-java-weak-cipher
        Cipher d = Cipher.getInstance("AES");
        // ok: pandaward-java-weak-cipher
        Cipher e = Cipher.getInstance("AES/GCM/NoPadding");
    }

    void hashes() throws Exception {
        // ruleid: pandaward-java-weak-hash
        MessageDigest a = MessageDigest.getInstance("MD5");
        // ruleid: pandaward-java-weak-hash
        MessageDigest b = java.security.MessageDigest.getInstance("sha1", "SUN");
        // ok: pandaward-java-weak-hash
        MessageDigest c = MessageDigest.getInstance("SHA-256");
    }

    void tokens() throws Exception {
        // ruleid: pandaward-java-weak-random
        long a = new Random().nextLong();
        // ruleid: pandaward-java-weak-random
        double b = Math.random();
        // ok: pandaward-java-weak-random
        long c = new SecureRandom().nextLong();
    }

    void cookies(HttpServletResponse response) {
        Cookie a = new Cookie("session", "x");
        // ruleid: pandaward-java-insecure-cookie
        a.setSecure(false);
        Cookie b = new Cookie("session", "y");
        // ok: pandaward-java-insecure-cookie
        b.setSecure(true);
        response.addCookie(a);
        response.addCookie(b);
    }
}
