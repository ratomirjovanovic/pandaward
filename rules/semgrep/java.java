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
        // ruleid: pensec-java-sql-string
        st.executeQuery("SELECT * FROM invoices WHERE id = " + id);
        // ok: pensec-java-sql-string
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM invoices WHERE id = ?");
        ps.setString(1, id);
    }

    void run(String dir) throws Exception {
        // ruleid: pensec-java-command-exec
        Runtime.getRuntime().exec("ls " + dir);
        // ok: pensec-java-command-exec
        Runtime.getRuntime().exec("ls -la");
        // ruleid: pensec-java-command-exec
        new ProcessBuilder("sh", "-c", "ls " + dir).start();
        // ok: pensec-java-command-exec
        new ProcessBuilder("ls", dir).start();
    }

    Object load(InputStream in) throws Exception {
        // ruleid: pensec-java-deserialization
        return new ObjectInputStream(in).readObject();
    }

    Object loadJson(InputStream in) throws Exception {
        // ok: pensec-java-deserialization
        return new com.fasterxml.jackson.databind.ObjectMapper().readValue(in, Object.class);
    }

    void crypto() throws Exception {
        // ruleid: pensec-java-weak-cipher
        Cipher a = Cipher.getInstance("DES");
        // ruleid: pensec-java-weak-cipher
        Cipher b = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: pensec-java-weak-cipher
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    void files(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // ruleid: pensec-java-path-traversal
        FileInputStream in = new FileInputStream(name);
        // ok: pensec-java-path-traversal
        File safe = new File("/srv/files", FilenameUtils.getName(name));
    }

    void proxy(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        // ruleid: pensec-java-ssrf
        URL u = new URL(target);
        // ok: pensec-java-ssrf
        URL s = new URL("https://api.example.org/status");
    }
}
