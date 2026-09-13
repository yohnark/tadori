//go:build windows

package proxy

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// These APIs are native WinHTTP APIs. In particular, no command interpreter,
// PowerShell, registry shell, or PAC script engine is involved.
var (
	winhttpDLL                     = syscall.NewLazyDLL("winhttp.dll")
	getDefaultProxyConfiguration   = winhttpDLL.NewProc("WinHttpGetDefaultProxyConfiguration")
	getIEProxyConfigForCurrentUser = winhttpDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	kernel32DLL                    = syscall.NewLazyDLL("kernel32.dll")
	globalFree                     = kernel32DLL.NewProc("GlobalFree")
)

const (
	winHTTPAccessTypeNoProxy        = 1
	winHTTPAccessTypeNamedProxy     = 3
	winHTTPAccessTypeAutomaticProxy = 4
)

type winHTTPProxyInfo struct {
	dwAccessType    uint32
	lpszProxy       *uint16
	lpszProxyBypass *uint16
}

type winHTTPCurrentUserIEProxyConfig struct {
	fAutoDetect       int32
	lpszAutoConfigURL *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

func discoverPlatform(ctx context.Context) (Discovery, error) {
	if err := ctx.Err(); err != nil {
		return Discovery{}, err
	}
	winHTTP, _ := queryWinHTTP()
	if err := ctx.Err(); err != nil {
		return Discovery{}, err
	}
	winINET, _ := queryWinINET()
	// Keep both source records even when both calls fail. The caller can then
	// report WinHTTP and WinINET independently as unavailable instead of
	// collapsing the two observations into one generic error.
	return Discovery{WinHTTP: winHTTP, WinINET: winINET}, nil
}

func queryWinHTTP() (SourceConfiguration, error) {
	var info winHTTPProxyInfo
	ret, _, _ := getDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return SourceConfiguration{Available: false, Error: "WinHTTP configuration unavailable"}, errors.New("WinHTTP configuration unavailable")
	}
	defer freeGlobal(info.lpszProxy)
	defer freeGlobal(info.lpszProxyBypass)
	return SourceConfiguration{
		Available:  true,
		Proxy:      readUTF16(info.lpszProxy),
		Bypass:     splitBypass(readUTF16(info.lpszProxyBypass)),
		AutoDetect: info.dwAccessType == winHTTPAccessTypeAutomaticProxy,
	}, nil
}

func queryWinINET() (SourceConfiguration, error) {
	var info winHTTPCurrentUserIEProxyConfig
	ret, _, _ := getIEProxyConfigForCurrentUser.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return SourceConfiguration{Available: false, Error: "WinINET configuration unavailable"}, errors.New("WinINET configuration unavailable")
	}
	defer freeGlobal(info.lpszAutoConfigURL)
	defer freeGlobal(info.lpszProxy)
	defer freeGlobal(info.lpszProxyBypass)
	return SourceConfiguration{
		Available:  true,
		Proxy:      readUTF16(info.lpszProxy),
		Bypass:     splitBypass(readUTF16(info.lpszProxyBypass)),
		PACURL:     readUTF16(info.lpszAutoConfigURL),
		AutoDetect: info.fAutoDetect != 0,
	}, nil
}

func freeGlobal(value *uint16) {
	if value != nil {
		_, _, _ = globalFree.Call(uintptr(unsafe.Pointer(value)))
	}
}

func readUTF16(value *uint16) string {
	if value == nil {
		return ""
	}
	// Native configuration strings are bounded by the Windows registry/API;
	// retaining a hard cap also prevents malformed native data from causing an
	// unbounded read.
	const maxProxyString = 1 << 16
	values := unsafe.Slice(value, maxProxyString)
	for index, character := range values {
		if character == 0 {
			return syscall.UTF16ToString(values[:index])
		}
	}
	return syscall.UTF16ToString(values)
}

func splitBypass(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
