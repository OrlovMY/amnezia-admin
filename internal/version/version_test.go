package version

import "testing"

// TestVersionStringDefault доказывает: без -ldflags String() == "dev (unknown)".
func TestVersionStringDefault(t *testing.T) {
	t.Cleanup(func() {
		Version = "dev"
		Commit = "unknown"
	})
	Version = "dev"
	Commit = "unknown"

	got := String()
	want := "dev (unknown)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

// TestVersionStringFormat доказывает точную форму (П19): версия + первые 7
// символов коммита в скобках; короткий коммит — целиком; пустая версия — "dev".
func TestVersionStringFormat(t *testing.T) {
	orig := Version
	origCommit := Commit
	t.Cleanup(func() {
		Version = orig
		Commit = origCommit
	})

	cases := []struct {
		name    string
		version string
		commit  string
		want    string
	}{
		{
			name:    "полная версия и длинный коммит",
			version: "v1.2.3",
			commit:  "abcdef0123456789",
			want:    "v1.2.3 (abcdef0)",
		},
		{
			name:    "короткий коммит целиком",
			version: "v1.2.3",
			commit:  "abc",
			want:    "v1.2.3 (abc)",
		},
		{
			name:    "пустая версия -> dev",
			version: "",
			commit:  "abcdef0123456789",
			want:    "dev (abcdef0)",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			Version = c.version
			Commit = c.commit
			got := String()
			if got != c.want {
				t.Fatalf("String() = %q, want %q", got, c.want)
			}
		})
	}
}
