//Copyright 2014 sndnvaps
//
package selinux_test

import (
	"fmt"
	"os"
	"testing"

	se "github.com/sndnvaps/selinux"
)

func TestSelinux_enabled(t *testing.T) {
	if se.Enabled() {
		fmt.Println("SELinux status = Enabled")
	} else {
		fmt.Println("SELinux status = Disabled")
	}
}

func TestGetfilecon(t *testing.T) {
	var flabel string
	var size int
	flabel, size = se.Lgetfilecon("selinux.go")
	if size > 0 {
		fmt.Println("selinux.go label = ", flabel)
	}
}

func TestSetfilecon(t *testing.T) {
	path := "selinux.go"
	scon := "system_u:object_r:usr_t:s0"
	rc, _ := se.Lsetfilecon(path, scon)
	if rc != 0 {
		fmt.Println("Setfilecon failed")
	} else {
		fmt.Println("Setfilecon success")
	}
}

// fd := f.Fd()
// os.Fileinfo
func TestFsetfilecon(t *testing.T) {
	f, err := os.Create("test.selinux")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	fd := int(f.Fd())

	scon := "system_u:object_r:usr_t:s0"
	rc, _ := se.Fsetfilecon(fd, scon)
	if rc != 0 {
		fmt.Println("fsetfilecon failed")
	} else {
		fmt.Println("fsetfilecon: test.selinux -> ", scon)
	}
}

func TestMatchpathcon(t *testing.T) {
	path := "selinux_test.go"
	mode, ecode := se.GetModeT(path)
	if ecode == 0 {
		con, err := se.Matchpathcon(path, mode)
		if err != nil {
			fmt.Println("selinux_test.go selabel = ", con)
		}
	}
}

func TestSelinux_getenforcemode(t *testing.T) {
	var enforce int
	enforce = se.Getenforcemode()
	fmt.Printf("%s", "Selinux mode = ")
	if enforce == se.Enforcing {
		fmt.Println("Enforcing mode")
	} else if enforce == se.Permissive {
		fmt.Println("permissive mode")
	} else if enforce == se.Disabled {
		fmt.Println("Disabled mode")
	}
}
func TestGetPidcon(t *testing.T) {
	pid := os.Getpid()
	fmt.Printf("PID:%d MCS:%s\n", pid, se.IntToMcs(pid, 1023))
	if scon, err := se.Getpidcon(pid); err == nil {
		fmt.Printf("pid = %d, security_context = %s ", pid, scon)
	}
}

func TestLgetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		fmt.Println(err)
	}
	fcXattr, err := se.Lgetxattr(fc.Name(), se.SecuritySelinux)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("se_xattrs_test.txt xattr = ", string(fcXattr))
	}

}

func TestLsetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		fmt.Println(err)
	}
	scon := "system_u:object_r:usr_t:s0"
	err = se.Lsetxattr(fc.Name(), se.SecuritySelinux, []byte(scon), 0)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("set ", fc.Name(), "selinux_label -> ", scon, "success")
	}

}

func TestFgetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test_fd.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		fmt.Println(err)
	}
	fcXattr, err := se.Fgetxattr(fc.Fd(), se.SecuritySelinux)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("TestFgetxattr:se_xattrs_test.txt xattr = ", string(fcXattr))
	}

}

func TestFsetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test_fd.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		fmt.Println(err)
	}

	scon := "system_u:object_r:usr_t:s0"

	err = se.Fsetxattr(fc.Fd(), se.SecuritySelinux, []byte(scon), 0)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("TestFsetxattr:se_xattrs_test_fd.txt xattr = ", scon)
	}

}
