package redact

import (
	"strings"
	"testing"
)

func TestLineRedactsSecrets(t *testing.T) {
	aws := "AKIA" + "Q3EGRZ7X2MNT4KPL"
	gh := "ghp_" + strings.Repeat("x9Y8", 9)
	cases := []string{
		`aws_key = "` + aws + `"`,
		`token: ` + gh,
		`Authorization: Bearer abcdef0123456789abcdef`,
		`password = "hunter2hunter2"`,
		`DATABASE_URL=postgres://app:s3cretpw@db:5432/app`,
		`Set-Cookie: sid=0123456789abcdef; HttpOnly`,
	}
	secrets := []string{aws, gh, "abcdef0123456789abcdef", "hunter2hunter2", "s3cretpw", "0123456789abcdef"}
	for i, c := range cases {
		out := Line(c)
		if strings.Contains(out, secrets[i]) {
			t.Errorf("not redacted: %q -> %q", c, out)
		}
	}
	if got := Line("user email jane.doe@example.org"); strings.Contains(got, "jane.doe") {
		t.Errorf("email not masked: %s", got)
	}
}

func TestSanitizeStripsControl(t *testing.T) {
	if s := Sanitize("ok\x1b[31mred\x1b[0m‮evil"); strings.ContainsAny(s, "\x1b‮") {
		t.Fatalf("control characters remain: %q", s)
	}
}

func TestPlaceholdersKept(t *testing.T) {
	if s := Line(`password = process.env.DB_PASSWORD`); !strings.Contains(s, "process.env") {
		t.Fatalf("placeholder should be kept: %s", s)
	}
}
