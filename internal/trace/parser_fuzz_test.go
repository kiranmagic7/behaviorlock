package trace

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add("execve(\"/bin/sh\", [\"sh\", \"-c\", \"true\"], 0x0) = 0\n")
	f.Add("connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"198.51.100.1\")}, 16) = -1 ENETUNREACH (Network is unreachable)\n")
	f.Add("openat(AT_FDCWD, \"/home/scanner/.ssh/id_rsa\", O_RDONLY) = 3\n")
	f.Add("[pid 101] sendto(3<socket:[1]>, \"query\", 5, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"198.51.100.53\")}, 16) = -1 ENETUNREACH (Network is unreachable)\n")
	f.Add("[pid 102] openat(AT_FDCWD, \"/work/x\", O_RDWR <unfinished ...>\n[pid 102] <... openat resumed>) = 3</work/x>\n")
	f.Add("103 openat(AT_FDCWD, \"/work/x\", O_RDWR|O_CLOEXEC) = 3</work/x>\n103 execve(\"/bin/true\", [\"true\"], 0x0) = 0\n103 ftruncate(3, 0) = -1 EBADF (Bad file descriptor)\n")
	f.Add("[pid 33] 1786329664.837566 listen(19, 511)       = 0\n")
	f.Fuzz(func(t *testing.T, value string) {
		first, firstErr := Parse(strings.NewReader(value))
		second, secondErr := Parse(strings.NewReader(value))
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("parser error outcome is nondeterministic")
		}
		if firstErr == nil && len(first.Behaviors) != len(second.Behaviors) {
			t.Fatal("parser behavior count is nondeterministic")
		}
	})
}
