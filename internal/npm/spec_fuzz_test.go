package npm

import "testing"

func FuzzParseExactSpec(f *testing.F) {
	f.Add("lodash@4.17.21")
	f.Add("@scope/package@1.2.3")
	f.Add("pkg@latest")
	f.Add("pkg@1.0.0;touch /tmp/no")
	f.Fuzz(func(t *testing.T, value string) {
		spec, err := ParseExactSpec(value)
		if err != nil {
			return
		}
		if spec.String() != value {
			t.Fatalf("accepted spec did not round trip: %q became %q", value, spec.String())
		}
		if spec.Name == "" || spec.Version == "" || spec.PURL() == "" {
			t.Fatalf("accepted spec has empty normalized fields: %#v", spec)
		}
	})
}
