package selinux

/*
 The selinux package is a go bindings to libselinux required to add selinux
 support to docker.

 Author Dan Walsh <dwalsh@redhat.com>

 Used some ideas/code from the go-ini packages https://github.com/vaughan0
 By Vaughan Newton

2014-06-10 22:02:58
   Contributor : sndnvaps <sndnvaps@gmail.com>
   remove some dead code

*/
// use deepin linux 2013.1
// kernel requre 3.8
// libselinux == 2.3

// //cgo  linux CFLAGS: -Iinclude -I.
// #cgo pkg-config: libselinux
// #include <selinux/selinux.h>
// #include <selinux/label.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <sys/types.h>
// #include <sys/stat.h>
import "C"
import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"path"
	"path/filepath"
	"unsafe"
	//"bufio"
	"regexp"
	//"io"
	//"os"
	//"strconv"
	"strings"
	"syscall"
)

var (
	assignRegex = regexp.MustCompile(`^([^=]+)=(.*)$`)
	mcsList     = make(map[string]bool)
)

//File attribute names
const (
	SecurityCapability = "security.capability" // for get capability from xattr
	SecuritySelinux    = "security.selinux"    //for get selinux_label from xattr
)

// C.mode_t

// Lgetxattr Returns a nil slice and nil error if the xattr is not set
func Lgetxattr(path string, attr string) ([]byte, error) {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	attrBytes, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 128)
	destBytes := unsafe.Pointer(&dest[0])
	sz, _, errno := syscall.Syscall6(syscall.SYS_LGETXATTR, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(attrBytes)), uintptr(destBytes), uintptr(len(dest)), 0, 0)
	if errno == syscall.ENODATA {
		return nil, nil
	}
	if errno == syscall.ERANGE {
		dest = make([]byte, sz)
		destBytes := unsafe.Pointer(&dest[0])
		sz, _, errno = syscall.Syscall6(syscall.SYS_LGETXATTR, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(attrBytes)), uintptr(destBytes), uintptr(len(dest)), 0, 0)
	}
	if errno != 0 {
		return nil, errno
	}

	return dest[:sz], nil
}

var _zero uintptr

//Lsetxattr sets the attribute on the file
func Lsetxattr(path string, attr string, data []byte, flags int) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	attrBytes, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return err
	}
	var dataBytes unsafe.Pointer
	if len(data) > 0 {
		dataBytes = unsafe.Pointer(&data[0])
	} else {
		dataBytes = unsafe.Pointer(&_zero)
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LSETXATTR, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(attrBytes)), uintptr(dataBytes), uintptr(len(data)), uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

//Fgetxattr os.File.Fd() uintptr
func Fgetxattr(fd uintptr, attr string) ([]byte, error) {
	attrBytes, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return nil, err
	}
	dest := make([]byte, 128)
	destBytes := unsafe.Pointer(&dest[0])
	sz, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, fd, uintptr(unsafe.Pointer(attrBytes)), uintptr(destBytes), uintptr(len(dest)), 0, 0)
	if errno == syscall.ENODATA {
		return nil, nil
	}
	if errno == syscall.ERANGE {
		dest = make([]byte, sz)
		destBytes := unsafe.Pointer(&dest[0])
		syscall.Syscall6(syscall.SYS_FSETXATTR, fd, uintptr(unsafe.Pointer(attrBytes)), uintptr(destBytes), uintptr(len(dest)), 0, 0)
	}

	if errno != 0 {
		return nil, errno
	}

	return dest[:sz], nil
}

//Fsetxattr sets the extended attribute
func Fsetxattr(fd uintptr, attr string, data []byte, flags int) error {

	attrBytes, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return err
	}
	var dataBytes unsafe.Pointer
	if len(data) > 0 {
		dataBytes = unsafe.Pointer(&data[0])
	} else {
		dataBytes = unsafe.Pointer(&_zero)
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_FSETXATTR, fd, uintptr(unsafe.Pointer(attrBytes)), uintptr(dataBytes), uintptr(len(data)), uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

//GetModeT gets the c mode
func GetModeT(path string) (C.mode_t, int) {
	var st C.struct_stat
	var mode C.mode_t
	var result C.int
	if result = C.stat(C.CString(path), &st); result == (C.int(0)) {
		mode = C.mode_t(st.st_mode)
		return C.mode_t(st.st_mode), 0
	}
	return mode, -1 //cannot find the file
}

//Matchpathcon determines the expected permissions for a given path
func Matchpathcon(path string, mode C.mode_t) (string, error) {
	var con *C.char
	var scon string
	rc, err := C.matchpathcon(C.CString(path), mode, &con)
	if rc == 0 {
		scon = C.GoString(con)
		C.free(unsafe.Pointer(con))
	}
	return scon, err

}

//Lsetfilecon sets the permissions for a path
func Lsetfilecon(path, scon string) (int, error) {
	rc, err := C.lsetfilecon(C.CString(path), C.CString(scon))
	return int(rc), err
}

//Setfilecon sets the permissions on a path
func Setfilecon(path, scon string) (int, error) {
	rc, err := C.setfilecon(C.CString(path), C.CString(scon))
	return int(rc), err
}

//os.File.fd int
/*
f , err os.Open(file)
if err != nil {
	fd := int(f.Fd())
Fsetfilecon(fd, scon)
*/

//Fsetfilecon rc == 0 -> success
func Fsetfilecon(fd int, scon string) (int, error) {
	var con *C.char
	con = C.CString(scon)
	rc, err := C.fsetfilecon(C.int(fd), con)
	return int(rc), err
}

//Lgetfilecon return selabel , sizeof(selabel)
func Lgetfilecon(path string) (string, int) {
	var scon string
	var con *C.char
	//con = C.CString(scon)
	rc, _ := C.lgetfilecon(C.CString(path), &con)
	fmt.Println(C.GoString(con))
	if rc > 0 {
		scon = C.GoString(con)
		C.free(unsafe.Pointer(con))
	}
	return scon, int(rc)
}

//SelabelLookup this func not work
func SelabelLookup(name string, mode int) (string, error) {
	var con *C.char
	//var sehandel C.selhandle
	var sehandle *C.struct_selabel_handle
	/*
		var st C.struct_stat
		rc, _ := C.stat(C.CString(name), &st)
		if rc == 0 {
		mode = int(st.st_mode)
		}
	*/

	//var sehandel *C.selabel_handle
	//sehandel := NewSelabel_handle()
	var scon string
	rc, err := C.selabel_lookup(sehandle, &con, C.CString(name), C.int(mode))
	if rc == 0 {
		scon = C.GoString(con)
		//C.free(con)
		//C.free(sehandel)
	}
	return scon, err
}

//Setfscreatecon sets the default creation label
func Setfscreatecon(scon string) (int, error) {
	var (
		rc  C.int
		err error
	)
	if scon != "" {
		rc, err = C.setfscreatecon(C.CString(scon))
	} else {
		rc, err = C.setfscreatecon(nil)
	}
	return int(rc), err
}

//Getfscreatecon gets the default create label
func Getfscreatecon() (string, error) {
	var scon *C.char
	var fcon string
	rc, err := C.getfscreatecon(&scon)
	if rc >= 0 {
		fcon = C.GoString(scon)
		err = nil
		C.freecon(scon)
	}
	return fcon, err
}

//Getcon gets the selinux context
func Getcon() string {
	var pcon *C.char
	C.getcon(&pcon)
	scon := C.GoString(pcon)
	C.freecon(pcon)
	return scon
}

//Getpidcon gets the selinux context for a given pid
func Getpidcon(pid int) (string, error) {
	var pcon *C.char
	var scon string
	rc, err := C.getpidcon(C.pid_t(pid), &pcon)
	if rc >= 0 {
		scon = C.GoString(pcon)
		C.freecon(pcon)
		err = nil
	}
	return scon, err
}

//Getpeercon gets the selinux context for a given peer
func Getpeercon(socket int) (string, error) {
	var pcon *C.char
	var scon string
	rc, err := C.getpeercon(C.int(socket), &pcon)
	if rc >= 0 {
		scon = C.GoString(pcon)
		C.freecon(pcon)
		err = nil
	}
	return scon, err
}

//Setexeccon sets the context for processes that are executed from here
func Setexeccon(scon string) (int, error) {
	var val *C.char
	if !Enabled() {
		return 0, nil
	}
	if scon != "" {
		val = C.CString(scon)
	} else {
		val = nil
	}
	rc, err := C.setexeccon(val)
	return int(rc), err
}

//Context is an selinux context
type Context struct {
	con []string
}

//SetUser sets the context user
func (c *Context) SetUser(user string) {
	c.con[0] = user
}

//GetUser sets the context user
func (c *Context) GetUser() string {
	return c.con[0]
}

//SetRole sets the context user
func (c *Context) SetRole(role string) {
	c.con[1] = role
}

//GetRole sets the context user
func (c *Context) GetRole() string {
	return c.con[1]
}

//SetType sets the context
func (c *Context) SetType(setype string) {
	c.con[2] = setype
}

//GetType sets the context
func (c *Context) GetType() string {
	return c.con[2]
}

//SetLevel sets the context
func (c *Context) SetLevel(mls string) {
	c.con[3] = mls
}

//GetLevel gets the context
func (c *Context) GetLevel() string {
	return c.con[3]
}

//Get gets the context
func (c *Context) Get() string {
	return strings.Join(c.con, ":")
}

//Set sets the context
func (c *Context) Set(scon string) {
	c.con = strings.SplitN(scon, ":", 4)
}

//NewContext sets the context user
func NewContext(scon string) Context {
	var con Context
	con.Set(scon)
	return con
}

//IsSelinuxEnabled checks the selinux status
func IsSelinuxEnabled() bool {
	b := C.is_selinux_enabled()
	if b > 0 {
		return true
	}
	return false
}

//Enabled checks the selinux status
func Enabled() bool {
	b := C.is_selinux_enabled()
	if b > 0 {
		return true
	}
	return false
}

//Default Selinux modes
const (
	Enforcing  = 1
	Permissive = 0
	Disabled   = -1
)

//Getenforce determines the enforcement mode
func Getenforce() int {
	return int(C.security_getenforce())
}

//Getenforcemode gets the mode
func Getenforcemode() int {
	var enforce C.int
	enforce = C.selinux_getenforcemode(&enforce)
	return int(enforce)
}

func mcsAdd(mcs string) {
	mcsList[mcs] = true
}

func mcsDelete(mcs string) {
	mcsList[mcs] = false
}

func mcsExists(mcs string) bool {
	return mcsList[mcs]
}

//IntToMcs changes the into the correct mcs label
func IntToMcs(id int, catRange uint32) string {
	if (id < 1) || (id > 523776) {
		return ""
	}

	SETSIZE := int(catRange)
	TIER := SETSIZE

	ORD := id
	for ORD > TIER {
		ORD = ORD - TIER
		TIER--
	}
	TIER = SETSIZE - TIER
	ORD = ORD + TIER
	return fmt.Sprintf("s0:c%d,c%d", TIER, ORD)
}

func uniqMcs(catRange uint32) string {
	var n uint32
	var c1, c2 uint32
	var mcs string
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &n)
		c1 = n % catRange
		binary.Read(rand.Reader, binary.LittleEndian, &n)
		c2 = n % catRange
		if c1 == c2 {
			continue
		} else {
			if c1 > c2 {
				t := c1
				c1 = c2
				c2 = t
			}
		}
		mcs = fmt.Sprintf("s0:c%d,c%d", c1, c2)
		if mcsExists(mcs) {
			continue
		}
		mcsAdd(mcs)
		break
	}
	return mcs
}
func freeContext(processLabel string) {
	var scon Context
	scon = NewContext(processLabel)
	mcsDelete(scon.GetLevel())
}

/*
func Get_lxc_contexts() (process_label string, file_label string) {
	var val, key string
	var bufin *bufio.Reader
	if ! SelinuxEnabled() {
		return
	}
	lxc_path := C.GoString(C.selinux_lxc_contexts_path())
	file_label = "system_u:object_r:svirt_sandbox_file_t:s0"
	process_label = "system_u:system_r:svirt_lxc_net_t:s0"

	in, err := os.Open(lxc_path)
	if err != nil {
		goto exit
	}

	defer in.Close()
	bufin = bufio.NewReader(in)

	for done := false; !done; {
		var line string
		if line, err = bufin.ReadString('\n'); err != nil {
			if err == io.EOF {
				done = true
			} else {
				goto exit
			}
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			// Skip blank lines
			continue
		}
		if line[0] == ';' || line[0] == '#' {
			// Skip comments
			continue
		}
		if groups := assignRegex.FindStringSubmatch(line); groups != nil {
			key, val = strings.TrimSpace(groups[1]), strings.TrimSpace(groups[2])
			if key == "process" {
				process_label = strings.Trim(val,"\"")
			}
			if key == "file" {
				file_label = strings.Trim(val,"\"")
			}
		}
	}
exit:
	var scon Context
	mcs := uniq_mcs(1024)
	scon = New_context(process_label)
	scon.Set_level(mcs)
	process_label = scon.Get()
	scon = New_context(file_label)
	scon.Set_level(mcs)
	file_label = scon.Get()
	return process_label, file_label
}
*/

//CopyLevel preserves the selinux label
func CopyLevel(src, dest string) (string, error) {
	if !Enabled() {
		return "", nil
	}
	if src == "" {
		return "", nil
	}
	rc, err := C.security_check_context(C.CString(src))
	if rc != 0 {
		return "", err
	}
	rc, err = C.security_check_context(C.CString(dest))
	if rc != 0 {
		return "", err
	}
	scon := NewContext(src)
	tcon := NewContext(dest)
	tcon.SetLevel(scon.GetLevel())
	return tcon.Get(), nil
}

//RestoreCon relabels a given file path
func RestoreCon(fpath string, recurse bool) error {
	var flabel string
	var err error
	var fsMode C.mode_t
	var ecode int //error code

	if !Enabled() {
		return nil
	}

	if recurse {
		var paths []string
		var err error

		if paths, err = filepath.Glob(path.Join(fpath, "**", "*")); err != nil {
			return fmt.Errorf("Unable to find directory %v: %v", fpath, err)
		}

		for _, fpath := range paths {
			if err = RestoreCon(fpath, false); err != nil {
				return fmt.Errorf("Unable to restore selinux context for %v: %v", fpath, err)
			}
		}
		return nil
	}
	if fsMode, ecode = GetModeT(fpath); ecode != 0 {
		//if fs, err = os.Stat(fpath); err != nil {
		return fmt.Errorf("Unable stat %v: %v", fpath, err)
	}

	if flabel, err = Matchpathcon(fpath, fsMode); flabel == "" {
		return fmt.Errorf("Unable to get context for %v: %v", fpath, err)
	}

	if rc, err := Setfilecon(fpath, flabel); rc != 0 {
		return fmt.Errorf("Unable to set selinux context for %v: %v", fpath, err)
	}

	return nil
}
