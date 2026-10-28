import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.InputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class Fixture {
    void lookup(Connection conn, String id) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: pandaward-java-sql-string
        st.executeQuery("SELECT * FROM invoices WHERE id = " + id);
        // ok: pandaward-java-sql-string
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM invoices WHERE id = ?");
        ps.setString(1, id);
    }

    void run(String dir) throws Exception {
        // ruleid: pandaward-java-command-exec
        Runtime.getRuntime().exec("ls " + dir);
        // ok: pandaward-java-command-exec
        Runtime.getRuntime().exec("ls -la");
        // ruleid: pandaward-java-command-exec
        new ProcessBuilder("sh", "-c", "ls " + dir).start();
        // ok: pandaward-java-command-exec
        new ProcessBuilder("ls", dir).start();
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
        // ok: pandaward-java-weak-cipher
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    void files(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // ruleid: pandaward-java-path-traversal
        FileInputStream in = new FileInputStream(name);
        // ok: pandaward-java-path-traversal
        File safe = new File("/srv/files", FilenameUtils.getName(name));
    }

    void proxy(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        // ruleid: pandaward-java-ssrf
        URL u = new URL(target);
        // ok: pandaward-java-ssrf
        URL s = new URL("https://api.example.org/status");
    }
}
