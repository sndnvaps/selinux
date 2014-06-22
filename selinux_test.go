//Copyright 2014 sndnvaps 
//
package selinux_test 

import (
	. "selinux"
	"fmt"
	"testing"
	"os"
)

func TestSelinux_enabled(t *testing.T) { 
	if Selinux_enabled() {
		fmt.Println("SELinux status = Enabled\n")
		} else {
		fmt.Println("SELinux status = Disabled\n")
		}
}

func TestGetfilecon(t *testing.T) {
	var flabel string 
	var size int 
	flabel ,size = Lgetfilecon("selinux.go")
	if size > 0  {
	fmt.Println("selinux.go label = ", flabel)
	}
}

func TestSetfilecon(t *testing.T) {
	path := "selinux.go"
	scon := "system_u:object_r:usr_t:s0"
	rc , _ := Lsetfilecon(path, scon)
	if rc != 0  {
		fmt.Println("Setfilecon failed\n")
		} else {
		fmt.Println("Setfilecon success\n")
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
	rc, _ := Fsetfilecon(fd, scon)
	if rc != 0 {
	fmt.Println("fsetfilecon failed\n")
	} else {
	fmt.Println("fsetfilecon: test.selinux -> ", scon)
	}
}


func TestMatchpathcon(t *testing.T) {
	path := "selinux_test.go" 
	mode := GetMode_t(path)
	if mode != 0  {
		con, err := Matchpathcon(path, mode)
		if err != nil {
			fmt.Println("selinux_test.go selabel = ",con)
			}
		}
}


func TestSelinux_getenforcemode(t *testing.T) {
	var enforce int 
	enforce = Selinux_getenforcemode()
	fmt.Printf("%s","Selinux mode = ")
	if enforce == Enforcing {
		fmt.Println("Enforcing mode\n")
	} else if enforce == Permissive {
		fmt.Println("permissive mode\n")
	} else if enforce == Disabled {
		fmt.Println("Disabled mode\n")
	}
}


