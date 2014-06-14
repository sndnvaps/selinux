//Copyright 2014 sndnvaps 
//
package selinux_test 

import (
	. "selinux"
	"fmt"
	"testing"
	//"os"
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

func TestFsetfilecon(t *testing.T) {
	scon := "unconfined_u:object_r:user_home_t:s0"
	rc , _ := Lsetfilecon("selinux.go",scon) 
	if rc != 0 {
	fmt.Println("fsetfilecon failed\n")
	} else {
	fmt.Println("fsetfilecon: selinux.go -> ", scon)
	}
}


func TestMatchpathcon(t *testing.T) {
	path := "/home/sn/.vimrc" 
	mode := GetMode_t(path)
	if mode != 0  {
		con, err := Matchpathcon(path, mode)
		if err != nil {
			fmt.Println("/home/sn/.vimrc selabel = ",con)
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

	
	



