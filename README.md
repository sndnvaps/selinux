# selinux

# WHATS:


binding libselinux to golang 


# INSTALL:


To experment with selinux_go, you can just compile and run the test example 

```bash 
go get github.com/sndnvaps/selinux
cd /path/to/selinux_go
go test 
  
```


# example 

```go 
// example.go 
package main

import (
	"github.com/sndnvaps/selinux_go"
	"fmt"
)

func main() {

	if selinux.Selinux_enabled() {
		fmt.Println("SELinux status = Enabled\n")
		} else {
		fmt.Println("SELinux status = Disabled\n")
		}
		
		
	path := "selinux_test"
	scon := "system_u:object_r:usr_t:s0"
	f, err := os.Create(path)
	var fd int 
	
	if err == nil {
	fd = int(f.Fd())
	}
	_ , e := selinux.Fsetfilecon(fd,scon) 
	
	if e == nil {
	fmt.Println("setfilecon success\n")
   }
   
}

```
		
	


# AUTHOR: 

- Dan Walsh <dwalsh@redhat.com>    //selinux.go author 
- dnvaps sn <sndnvaps@gmail.com>   //add libselinux code , and add more func 



