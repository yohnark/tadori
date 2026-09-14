//go:build windows

package proxy

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"unicode"
	"unsafe"
)

// These APIs are native WinHTTP APIs. In particular, no command interpreter,
// PowerShell, registry shell, or PAC script engine is involved.
var (
	winhttpDLL                     = syscall.NewLazyDLL("winhttp.dll")
	winhttpOpen                    = winhttpDLL.NewProc("WinHttpOpen")
	winhttpCloseHandle             = winhttpDLL.NewProc("WinHttpCloseHandle")
	winhttpSetTimeouts             = winhttpDLL.NewProc("WinHttpSetTimeouts")
	getDefaultProxyConfiguration   = winhttpDLL.NewProc("WinHttpGetDefaultProxyConfiguration")
	getIEProxyConfigForCurrentUser = winhttpDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	getProxyForURL                 = winhttpDLL.NewProc("WinHttpGetProxyForUrl")
	kernel32DLL                    = syscall.NewLazyDLL("kernel32.dll")
	globalFree                     = kernel32DLL.NewProc("GlobalFree")
)

const (
	winHTTPAccessTypeNoProxy        = 1
	winHTTPAccessTypeNamedProxy     = 3
	winHTTPAccessTypeAutomaticProxy = 4
	winHTTPAutoProxyDetect          = 1
	winHTTPAutoProxyConfigURL       = 2
	winHTTPAutoDetectDHCP           = 1
	winHTTPAutoDetectDNSA           = 2
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

type winHTTPAutoProxyOptions struct {
	dwFlags                uint32
	dwAutoDetectFlags      uint32
	lpszAutoConfigURL      *uint16
	lpvReserved            uintptr
	dwReserved             uint32
	fAutoLogonIfChallenged int32
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

func resolveProxyForURL(ctx context.Context, targetURL string, config SourceConfiguration) (URLProxyResolution, error) {
	if err := ctx.Err(); err != nil {
		return URLProxyResolution{}, err
	}
	if !config.Available {
		return URLProxyResolution{}, errors.New("proxy configuration unavailable")
	}

	// A static source needs no native URL resolution. Preserve the native
	// endpoint list only long enough to select a safe endpoint; it is never
	// returned verbatim.
	if strings.TrimSpace(config.PACURL) == "" && !config.AutoDetect {
		return resolveStaticProxyForURL(targetURL, config)
	}

	urlPointer, err := syscall.UTF16PtrFromString(targetURL)
	if err != nil {
		return URLProxyResolution{}, errors.New("invalid target URL")
	}
	userAgent, _ := syscall.UTF16PtrFromString("tadori")
	session, _, callErr := winhttpOpen.Call(
		uintptr(unsafe.Pointer(userAgent)),
		winHTTPAccessTypeNoProxy,
		0,
		0,
		0,
	)
	if session == 0 {
		if callErr != nil {
			return URLProxyResolution{}, errors.New("WinHTTP proxy resolver unavailable")
		}
		return URLProxyResolution{}, errors.New("WinHTTP proxy resolver unavailable")
	}
	defer winhttpCloseHandle.Call(session)
	// WinHttpGetProxyForUrl is synchronous. Set a native timeout as well as
	// honoring the caller context so an unavailable PAC source cannot outlive
	// the diagnostic's bounded operation.
	_, _, _ = winhttpSetTimeouts.Call(session, 5000, 5000, 5000, 5000)

	// Do not delegate credential acquisition to WinHTTP while diagnosing. A
	// challenged PAC source is evidence of a requirement, not permission to
	// access or emit the caller's credentials.
	options := winHTTPAutoProxyOptions{}
	if config.AutoDetect {
		options.dwFlags |= winHTTPAutoProxyDetect
		options.dwAutoDetectFlags = winHTTPAutoDetectDHCP | winHTTPAutoDetectDNSA
	}
	if config.PACURL != "" {
		// Remove user-info, query tokens, and fragments before passing a PAC
		// URL back to WinHTTP. The resolver only needs the PAC resource, and
		// diagnostics must never forward a captured secret unnecessarily.
		pacURL := sanitizePACURL(config.PACURL)
		if pacURL == "" {
			return URLProxyResolution{}, errors.New("invalid PAC URL")
		}
		pacPointer, pointerErr := syscall.UTF16PtrFromString(pacURL)
		if pointerErr != nil {
			return URLProxyResolution{}, errors.New("invalid PAC URL")
		}
		options.dwFlags |= winHTTPAutoProxyConfigURL
		options.lpszAutoConfigURL = pacPointer
	}

	var info winHTTPProxyInfo
	ret, _, _ := getProxyForURL.Call(session, uintptr(unsafe.Pointer(urlPointer)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return URLProxyResolution{}, errors.New("WinHTTP automatic proxy resolution failed")
	}
	defer freeGlobal(info.lpszProxy)
	defer freeGlobal(info.lpszProxyBypass)

	if err := ctx.Err(); err != nil {
		return URLProxyResolution{}, err
	}
	if info.dwAccessType == winHTTPAccessTypeNoProxy {
		bypass := splitBypass(readUTF16(info.lpszProxyBypass))
		return URLProxyResolution{
			Direct:        true,
			Bypass:        bypass,
			BypassMatched: ProxyBypasses(targetURL, bypass),
			UsedPAC:       true,
			AutoDetect:    config.AutoDetect,
			Configuration: string(StateDirect),
		}, nil
	}
	endpoint, direct, endpointErr := ProxyEndpointForURL(readUTF16(info.lpszProxy), targetURL)
	if endpointErr != nil {
		return URLProxyResolution{}, errors.New("WinHTTP returned a malformed proxy endpoint")
	}
	if direct || endpoint == "" {
		bypass := splitBypass(readUTF16(info.lpszProxyBypass))
		return URLProxyResolution{
			Direct:        true,
			Bypass:        bypass,
			BypassMatched: ProxyBypasses(targetURL, bypass),
			UsedPAC:       true,
			AutoDetect:    config.AutoDetect,
			Configuration: string(StateDirect),
		}, nil
	}
	bypass := splitBypass(readUTF16(info.lpszProxyBypass))
	return URLProxyResolution{
		Proxy:         endpoint,
		Bypass:        bypass,
		BypassMatched: false,
		UsedPAC:       true,
		AutoDetect:    config.AutoDetect,
		Configuration: string(StatePACConfigured),
	}, nil
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
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ',' || unicode.IsSpace(r) })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
