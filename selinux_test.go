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
	var err error 
	flabel ,err = Lgetfilecon("/home/sn/.vimrc")
	if err != nil {
		fmt.Println(err)
	} else {
	fmt.Println("/home/sn/.vimrc label = ", flabel)
	}
}

func TestSetfilecon(t *testing.T) {
	path := "/home/sn/.vimrc"
	scon := "system_u:object_r:usr_t:s0"
	_ , err := Lsetfilecon(path, scon)
	if err != nil {
		fmt.Println("Setfilecon failed\n")
		} else {
		fmt.Println("Setfilecon success\n")
		}
}

func TestFsetfilecon(t *testing.T) {
	f, err := os.Open("/home/sn/.vimrc")
	var fd int 
	if err != nil {
		fd = int(f.Fd())
	}

	scon := "unconfined_u:object_r:user_home_t:s0"
	_ , e := Fsetfilecon(fd,scon) 
	if e != nil {
	fmt.Println("fsetfilecon failed\n")
	} else {
	fmt.Println("fsetfilecon: vimrc -> ", scon)
	}
} 
/*
func TestSelabel_lookup(t *testing.T) {
	name := "/home/sn/.vimrc"
	//fstat , _ := os.Stat(name)
	//fmt.Println(fstat.Mode()) 	
	//mode := int(fstat.Mode())
	mode , _ := GetfileMode(name)
	if mode == -1 {
	return 
	}
	fmt.Println("mode = ", mode)
	flabel, err := Selabel_lookup(name, mode)
	if err != nil {
		fmt.Println("selabel_lookup selabel '/home/sn/.vimrc' = ",flabel)
	} else {
	fmt.Println("lookup selabel failed", err) 
	}
	
	
}
	
*/



