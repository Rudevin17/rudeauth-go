//go:build windows

package rudeauth

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// collectComponents reproduces the C++ SDK's Windows set exactly, so a device is
// recognised identically no matter which SDK authenticated it. Each component is
// tagged so two sources cannot collide on an identical value.
func collectComponents() []string {
	var out []string
	push := func(tag, v string) {
		if v != "" {
			out = append(out, tag+":"+v)
		}
	}
	push("machine-guid", regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid"))
	push("volume", volumeSerial())
	push("cpu", regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"))
	push("bios", regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemSerialNumber"))
	push("board", regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardProduct"))
	return out
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimRight(s, " \x00")
}

var procGetVolumeInformationW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetVolumeInformationW")

func volumeSerial() string {
	root, err := windows.UTF16PtrFromString(`C:\`)
	if err != nil {
		return ""
	}
	var serial uint32
	r1, _, _ := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(root)),
		0, 0,
		uintptr(unsafe.Pointer(&serial)),
		0, 0, 0, 0,
	)
	if r1 == 0 || serial == 0 {
		return ""
	}
	return fmt.Sprintf("%08X", serial)
}
