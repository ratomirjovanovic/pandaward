package adapters

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

func propsInventory(files map[string][]string) *inventory.Inventory {
	inv := &inventory.Inventory{}
	for path, lines := range files {
		inv.Files = append(inv.Files, &inventory.File{Path: path, Lang: "properties", Lines: lines})
	}
	return inv
}

func TestConfigAlgorithmRules(t *testing.T) {
	inv := propsInventory(map[string][]string{
		"src/main/resources/app.properties": {
			"# algorithms",
			"hashAlg1=MD5",
			"hashAlg2 = SHA-256",
			"cryptoAlg1: DES/ECB/PKCS5Padding",
			"cryptoAlg2=AES/GCM/NoPadding",
			"bad key=MD5",
			"! cryptoAlg3=RC4",
		},
	})
	got := string(configAlgorithmRules(inv))
	for _, want := range []string{
		"id: pandaward-java-weak-hash-config",
		`pattern: $P.getProperty("hashAlg1", ...)`,
		"id: pandaward-java-weak-cipher-config",
		`pattern: $P.getProperty("cryptoAlg1", ...)`,
		"java.security.MessageDigest.getInstance($ALG, ...)",
		"javax.crypto.Cipher.getInstance($ALG, ...)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, not := range []string{"hashAlg2", "cryptoAlg2", "cryptoAlg3", "bad key"} {
		if strings.Contains(got, `"`+not+`"`) {
			t.Errorf("%s must not be a source:\n%s", not, got)
		}
	}

	if configAlgorithmRules(propsInventory(map[string][]string{"a.properties": {"hash=SHA-512"}})) != nil {
		t.Error("no rule without a weak value")
	}
	if configAlgorithmRules(nil) != nil {
		t.Error("no rule without an inventory")
	}
}

// With semgrep installed, the generated rule reports MD5 from the properties
// file and not SHA-256.
func TestConfigAlgorithmRulesRun(t *testing.T) {
	bin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not installed")
	}
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	inv := propsInventory(map[string][]string{"app.properties": {"hashAlg1=MD5", "hashAlg2=SHA-256"}})
	if err := os.WriteFile(rule, configAlgorithmRules(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "Hash.java")
	code := `import java.security.MessageDigest;
import java.util.Properties;
class Hash {
  byte[] weak(Properties props, byte[] in) throws Exception {
    String algorithm = props.getProperty("hashAlg1", "SHA512");
    MessageDigest md = MessageDigest.getInstance(algorithm);
    return md.digest(in);
  }
  byte[] strong(Properties props, byte[] in) throws Exception {
    String algorithm = props.getProperty("hashAlg2", "SHA512");
    MessageDigest md = MessageDigest.getInstance(algorithm);
    return md.digest(in);
  }
}
`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "scan", "--config", rule, "--metrics=off", "--disable-version-check", "--quiet", "--json", src).Output()
	if err != nil {
		t.Fatalf("semgrep: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, `"line":6`) || strings.Contains(s, `"line":11`) {
		t.Fatalf("want a finding on line 6 only:\n%s", s)
	}
}
