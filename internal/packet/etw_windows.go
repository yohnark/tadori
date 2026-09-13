//go:build windows

package packet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/yohnark/tadori/internal/model"
	"golang.org/x/sys/windows"
)

const (
	etwNodeFlagTracedGUID = 0x00020000
	etwRealTimeMode       = 0x00000100
	etwProcessRealTime    = 0x00000100
	etwProcessEventRecord = 0x10000000
	etwHeader32Bit        = 0x0020
	etwStopSession        = 1
	etwEnableProvider     = 1

	etwKeywordDiagnosis   uint64 = 0x0000000000000080
	etwKeywordSendPath    uint64 = 0x0000000100000000
	etwKeywordReceivePath uint64 = 0x0000000200000000
	etwKeywordConnectPath uint64 = 0x0000000400000000
	etwKeywordGlobal      uint64 = 0x0000008000000000

	errorAccessDenied     = 5
	errorPrivilegeNotHeld = 1314
	errorNotSupported     = 50
	errorInvalidParameter = 87
	maxETWObservations    = 256
	maxETWFlows           = 256
)

var (
	etwTCPIPGUID      = windows.GUID{Data1: 0x2f07e2ee, Data2: 0x15db, Data3: 0x40f1, Data4: [8]byte{0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a}}
	etwSequence       atomic.Uint64
	etwAdvapi         = windows.NewLazySystemDLL("advapi32.dll")
	etwStartTrace     = etwAdvapi.NewProc("StartTraceW")
	etwControlTrace   = etwAdvapi.NewProc("ControlTraceW")
	etwEnableTraceEx2 = etwAdvapi.NewProc("EnableTraceEx2")
	etwOpenTrace      = etwAdvapi.NewProc("OpenTraceW")
	etwProcessTrace   = etwAdvapi.NewProc("ProcessTrace")
	etwCloseTrace     = etwAdvapi.NewProc("CloseTrace")
	etwCallbackSeq    atomic.Uint64
	etwCallbacks      sync.Map
)

// ETWBackend is the Windows in-box packet/flow evidence adapter. ETW is
// deliberately used for transport-stack events rather than installing a
// WFP/WinDivert/Npcap driver. Its supported observations are normalized by
// this package and never expose ETW payload buffers to the report.
type ETWBackend struct{}

// NewETWBackend constructs the Windows ETW backend.
func NewETWBackend() Backend { return &ETWBackend{} }

func (*ETWBackend) Start(ctx context.Context, scope Scope) (Capture, error) {
	if err := scope.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	sequence := etwSequence.Add(1)
	loggerName := fmt.Sprintf("TadoriPacket-%d-%d", windows.GetCurrentProcessId(), sequence)
	loggerUTF16, err := windows.UTF16FromString(loggerName)
	if err != nil {
		return nil, fmt.Errorf("ETW logger name: %w", err)
	}
	properties, propertyBytes := newETWProperties(loggerUTF16)

	capture := &etwCapture{
		scope:         scope,
		loggerName:    loggerName,
		loggerUTF16:   loggerUTF16,
		propertyBytes: propertyBytes,
		properties:    properties,
		done:          make(chan struct{}),
		tcbFlows:      make(map[uintptr]etwTCPFlow),
	}

	var traceHandle uint64
	status, _, _ := etwStartTrace.Call(uintptr(unsafe.Pointer(&traceHandle)), uintptr(unsafe.Pointer(&loggerUTF16[0])), uintptr(unsafe.Pointer(properties)))
	if status != 0 {
		return nil, etwStatusError(status, "StartTraceW")
	}
	capture.sessionHandle = traceHandle

	keywords := etwKeywordDiagnosis | etwKeywordSendPath | etwKeywordReceivePath | etwKeywordConnectPath | etwKeywordGlobal
	status, _, _ = etwEnableTraceEx2.Call(
		uintptr(traceHandle), uintptr(unsafe.Pointer(&etwTCPIPGUID)), uintptr(etwEnableProvider), uintptr(0xff),
		uintptr(keywords), 0, 0, 0,
	)
	if status != 0 {
		capture.stopNative()
		return nil, etwStatusError(status, "EnableTraceEx2")
	}

	callbackID := etwCallbackSeq.Add(1)
	logfile := &etwLogfile{
		LoggerName:          (*uint16)(unsafe.Pointer(&capture.loggerUTF16[0])),
		ProcessTraceMode:    etwProcessRealTime | etwProcessEventRecord,
		EventRecordCallback: windows.NewCallback(etwRecordCallback),
		Context:             uintptr(callbackID),
	}
	capture.callbackID = logfile.Context
	capture.logfile = logfile
	etwCallbacks.Store(capture.callbackID, capture)
	trace, _, lastErr := etwOpenTrace.Call(uintptr(unsafe.Pointer(logfile)))
	if trace == ^uintptr(0) || trace == 0 {
		capture.stopNative()
		capture.deleteCallback()
		if lastErr != nil {
			var errno windows.Errno
			if errors.As(lastErr, &errno) {
				return nil, etwStatusError(uintptr(errno), "OpenTraceW")
			}
			return nil, fmt.Errorf("OpenTraceW: %w", lastErr)
		}
		return nil, fmt.Errorf("OpenTraceW failed without an operating-system error")
	}
	capture.traceHandle = uint64(trace)

	go capture.process()
	go func() {
		select {
		case <-ctx.Done():
			capture.mu.Lock()
			capture.cancelled = true
			capture.mu.Unlock()
			capture.stopNative()
		case <-capture.done:
		}
	}()
	return capture, nil
}

type etwCapture struct {
	mu              sync.Mutex
	scope           Scope
	loggerName      string
	loggerUTF16     []uint16
	propertyBytes   []byte
	properties      *etwProperties
	sessionHandle   uint64
	traceHandle     uint64
	callbackID      uintptr
	logfile         *etwLogfile
	done            chan struct{}
	stopOnce        sync.Once
	observations    []model.PacketObservation
	tcbFlows        map[uintptr]etwTCPFlow
	eventsLost      uint64
	parseErrors     uint64
	processError    string
	cancelled       bool
	processComplete bool
}

type etwTCPFlow struct {
	localAddress  string
	localPort     uint16
	remoteAddress string
	remotePort    uint16
	processID     uint32
	connectionID  string
}

func (capture *etwCapture) process() {
	handle := capture.traceHandle
	status, _, _ := etwProcessTrace.Call(uintptr(unsafe.Pointer(&handle)), 1, 0, 0)
	capture.mu.Lock()
	if status != 0 && status != uintptr(windows.ERROR_CANCELLED) {
		capture.parseErrors++
		capture.processError = etwStatusError(status, "ProcessTrace").Error()
	}
	if capture.logfile != nil && uint64(capture.logfile.EventsLost) > capture.eventsLost {
		capture.eventsLost = uint64(capture.logfile.EventsLost)
	}
	if capture.properties != nil && uint64(capture.properties.EventsLost) > capture.eventsLost {
		capture.eventsLost = uint64(capture.properties.EventsLost)
	}
	if capture.parseErrors != 0 && capture.processError == "" {
		capture.processError = "ETW TCP/IP event decoding was incomplete"
	}
	capture.processComplete = true
	capture.mu.Unlock()
	capture.deleteCallback()
	close(capture.done)
}

func (capture *etwCapture) deleteCallback() {
	if capture.callbackID != 0 {
		etwCallbacks.Delete(capture.callbackID)
		capture.callbackID = 0
	}
}

func (capture *etwCapture) Stop() (CaptureResult, error) {
	capture.stopNative()
	<-capture.done
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := CaptureResult{
		Source:       "windows-etw/microsoft-windows-tcpip",
		Observations: append([]model.PacketObservation(nil), capture.observations...),
		Complete:     capture.processComplete && capture.parseErrors == 0 && capture.eventsLost == 0 && !capture.cancelled,
		EventsLost:   capture.eventsLost,
		Cancelled:    capture.cancelled,
		Error:        capture.processError,
	}
	return result, nil
}

func (capture *etwCapture) stopNative() {
	capture.stopOnce.Do(func() {
		if capture.sessionHandle != 0 {
			_, _, _ = etwEnableTraceEx2.Call(uintptr(capture.sessionHandle), uintptr(unsafe.Pointer(&etwTCPIPGUID)), 0, 0, 0, 0, 0, 0)
			_, _, _ = etwControlTrace.Call(uintptr(capture.sessionHandle), uintptr(unsafe.Pointer(&capture.loggerUTF16[0])), uintptr(unsafe.Pointer(capture.properties)), uintptr(etwStopSession))
		}
		if capture.traceHandle != 0 {
			_, _, _ = etwCloseTrace.Call(uintptr(capture.traceHandle))
		}
	})
}

func etwRecordCallback(record *etwRecord) uintptr {
	if record == nil || record.UserContext == 0 {
		return 0
	}
	value, ok := etwCallbacks.Load(record.UserContext)
	if !ok {
		return 0
	}
	capture, ok := value.(*etwCapture)
	if !ok {
		return 0
	}
	capture.consume(record)
	return 0
}

func (capture *etwCapture) consume(record *etwRecord) {
	if record.EventHeader.ProviderID != etwTCPIPGUID || record.UserData == 0 || record.UserDataLength == 0 {
		return
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if len(capture.observations) >= maxETWObservations {
		capture.eventsLost++
		return
	}
	payload := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), int(record.UserDataLength))
	eventID := record.EventHeader.EventDescriptor.ID
	var observations []model.PacketObservation
	var parseErr bool
	switch eventID {
	case 1002, 1182, 1183, 1184, 1185:
		flow, ok := parseETWTCPRequest(payload, record.EventHeader.Flags&etwHeader32Bit != 0, record.EventHeader.ProcessID)
		if !ok {
			parseErr = true
			break
		}
		flow.connectionID = fmt.Sprintf("tcb-%x", flow.tcb)
		if !capture.flowInScope(flow) {
			break
		}
		if _, exists := capture.tcbFlows[flow.tcb]; !exists && len(capture.tcbFlows) >= maxETWFlows {
			capture.eventsLost++
			break
		}
		capture.tcbFlows[flow.tcb] = etwTCPFlow{localAddress: flow.localAddress, localPort: flow.localPort, remoteAddress: flow.remoteAddress, remotePort: flow.remotePort, processID: flow.processID, connectionID: flow.connectionID}
		switch eventID {
		case 1183, 1184:
			observations = []model.PacketObservation{capture.tcpObservation(flow, model.PacketObservationTCPRST, model.PacketDirectionInbound, etwTimestamp(record.EventHeader.TimeStamp))}
		}
	case 1004:
		tcb, ok := parseETWPointer(payload, record.EventHeader.Flags&etwHeader32Bit != 0)
		if !ok {
			parseErr = true
			break
		}
		if flow, exists := capture.tcbFlows[tcb]; exists {
			observations = []model.PacketObservation{capture.tcpObservation(etwTCPRequestFlow{tcb: tcb, localAddress: flow.localAddress, localPort: flow.localPort, remoteAddress: flow.remoteAddress, remotePort: flow.remotePort, processID: flow.processID, connectionID: flow.connectionID}, model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, etwTimestamp(record.EventHeader.TimeStamp))}
		}
	case 1033:
		flow, ok := parseETWEndpointEvent(payload, record.EventHeader.Flags&etwHeader32Bit != 0)
		if !ok {
			parseErr = true
			break
		}
		if !capture.flowInScope(flow) {
			break
		}
		observations = []model.PacketObservation{capture.tcpObservation(flow, model.PacketObservationTCPHandshakeConfirmed, model.PacketDirectionInbound, etwTimestamp(record.EventHeader.TimeStamp))}
	case 1422:
		observation, ok := parseETWICMP(payload, record.EventHeader.TimeStamp, capture.scope)
		if !ok {
			parseErr = true
			break
		}
		if observation.Kind != "" {
			observations = []model.PacketObservation{observation}
		}
	}
	if parseErr {
		capture.parseErrors++
	}
	for _, observation := range observations {
		if !etwTargetCandidate(observation, capture.scope) {
			continue
		}
		observation.SessionID = capture.scope.Identity.SessionID
		observation.ProbeID = capture.scope.Identity.ProbeID
		observation.CorrelationID = capture.scope.Identity.CorrelationID
		observation.ID = fmt.Sprintf("%s/etw-%03d", capture.scope.Identity.CorrelationID, len(capture.observations)+1)
		capture.observations = append(capture.observations, model.NormalizePacketObservation(observation))
	}
}

func (capture *etwCapture) flowInScope(flow etwTCPRequestFlow) bool {
	if capture.scope.ProcessID != 0 && flow.processID != 0 && flow.processID != capture.scope.ProcessID {
		return false
	}
	return etwTargetCandidate(capture.tcpObservation(flow, model.PacketObservationOutboundTCPSYN, model.PacketDirectionOutbound, time.Time{}), capture.scope)
}

type etwTCPRequestFlow struct {
	tcb           uintptr
	localAddress  string
	localPort     uint16
	remoteAddress string
	remotePort    uint16
	processID     uint32
	connectionID  string
}

func (capture *etwCapture) tcpObservation(flow etwTCPRequestFlow, kind model.PacketObservationKind, direction model.PacketDirection, observedAt time.Time) model.PacketObservation {
	sourceAddress, sourcePort := flow.localAddress, flow.localPort
	destinationAddress, destinationPort := flow.remoteAddress, flow.remotePort
	if direction == model.PacketDirectionInbound {
		sourceAddress, sourcePort = flow.remoteAddress, flow.remotePort
		destinationAddress, destinationPort = flow.localAddress, flow.localPort
	}
	return model.PacketObservation{
		Kind: kind, Protocol: model.PacketProtocolTCP, Direction: direction,
		LocalAddress: flow.localAddress, LocalPort: flow.localPort,
		SourceAddress: sourceAddress, SourcePort: sourcePort,
		DestinationAddress: destinationAddress, DestinationPort: destinationPort,
		ProcessID: flow.processID, ConnectionID: flow.connectionID, ObservedAt: observedAt,
	}
}

func parseETWTCPRequest(payload []byte, header32 bool, processID uint32) (etwTCPRequestFlow, bool) {
	reader := newETWReader(payload)
	tcb, ok := reader.pointer(header32)
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	localLength, ok := reader.u32()
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	local, ok := reader.bytes(int(localLength))
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	remoteLength, ok := reader.u32()
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	remote, ok := reader.bytes(int(remoteLength))
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	localAddress, localPort := etwSocketAddress(local)
	remoteAddress, remotePort := etwSocketAddress(remote)
	return etwTCPRequestFlow{tcb: tcb, localAddress: localAddress, localPort: localPort, remoteAddress: remoteAddress, remotePort: remotePort, processID: processID}, localAddress != "" && remoteAddress != ""
}

func parseETWEndpointEvent(payload []byte, header32 bool) (etwTCPRequestFlow, bool) {
	reader := newETWReader(payload)
	localLength, ok := reader.u32()
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	local, ok := reader.bytes(int(localLength))
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	remoteLength, ok := reader.u32()
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	remote, ok := reader.bytes(int(remoteLength))
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	status, ok := reader.u32()
	if !ok || status != 0 {
		return etwTCPRequestFlow{}, false
	}
	processID, ok := reader.u32()
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	if _, ok := reader.u32(); !ok { // compartment
		return etwTCPRequestFlow{}, false
	}
	tcb, ok := reader.pointer(header32)
	if !ok {
		return etwTCPRequestFlow{}, false
	}
	localAddress, localPort := etwSocketAddress(local)
	remoteAddress, remotePort := etwSocketAddress(remote)
	connectionID := ""
	if tcb != 0 {
		connectionID = fmt.Sprintf("tcb-%x", tcb)
	}
	return etwTCPRequestFlow{tcb: tcb, localAddress: localAddress, localPort: localPort, remoteAddress: remoteAddress, remotePort: remotePort, processID: processID, connectionID: connectionID}, localAddress != "" && remoteAddress != ""
}

func parseETWPointer(payload []byte, header32 bool) (uintptr, bool) {
	reader := newETWReader(payload)
	return reader.pointer(header32)
}

func parseETWICMP(payload []byte, timestamp int64, scope Scope) (model.PacketObservation, bool) {
	reader := newETWReader(payload)
	transport, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	direction, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	icmpType, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	icmpCode, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	if _, ok := reader.u32(); !ok { // compartment
		return model.PacketObservation{}, false
	}
	sourceLength, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	source, ok := reader.bytes(int(sourceLength))
	if !ok {
		return model.PacketObservation{}, false
	}
	destinationLength, ok := reader.u32()
	if !ok {
		return model.PacketObservation{}, false
	}
	destination, ok := reader.bytes(int(destinationLength))
	if !ok {
		return model.PacketObservation{}, false
	}
	sourceAddress, _ := etwSocketAddress(source)
	destinationAddress, _ := etwSocketAddress(destination)
	if sourceAddress == "" || destinationAddress == "" {
		return model.PacketObservation{}, false
	}
	kind := model.PacketObservationKind("")
	if (direction == 0 && (icmpType == 8 || icmpType == 128)) ||
		(direction == 1 && (icmpType == 0 || icmpType == 129)) {
		if direction == 0 {
			kind = model.PacketObservationOutboundICMPEcho
		} else {
			kind = model.PacketObservationInboundICMPEcho
		}
	} else if (transport == 1 && icmpType == 11) || (transport == 58 && icmpType == 3) {
		kind = model.PacketObservationICMPTimeExceeded
	} else if (transport == 1 && icmpType == 3) || (transport == 58 && icmpType == 1) {
		kind = model.PacketObservationICMPUnreachable
	}
	if kind == "" {
		return model.PacketObservation{}, true
	}
	_ = scope
	packetDirection := model.PacketDirectionInbound
	if direction == 0 {
		packetDirection = model.PacketDirectionOutbound
	}
	return model.PacketObservation{
		Kind: kind, Protocol: model.PacketProtocolICMP, Direction: packetDirection,
		SourceAddress: sourceAddress, DestinationAddress: destinationAddress,
		ICMPType: uint8(icmpType), ICMPCode: uint8(icmpCode), ObservedAt: etwTimestamp(timestamp),
	}, true
}

type etwReader struct {
	data   []byte
	offset int
}

func newETWReader(data []byte) *etwReader { return &etwReader{data: data} }

func (reader *etwReader) bytes(length int) ([]byte, bool) {
	if length < 0 || reader.offset > len(reader.data)-length {
		return nil, false
	}
	value := reader.data[reader.offset : reader.offset+length]
	reader.offset += length
	return value, true
}

func (reader *etwReader) u8() (uint8, bool) {
	value, ok := reader.bytes(1)
	if !ok {
		return 0, false
	}
	return value[0], true
}

func (reader *etwReader) u16() (uint16, bool) {
	value, ok := reader.bytes(2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(value), true
}

func (reader *etwReader) u32() (uint32, bool) {
	value, ok := reader.bytes(4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(value), true
}

func (reader *etwReader) pointer(header32 bool) (uintptr, bool) {
	if header32 {
		value, ok := reader.u32()
		return uintptr(value), ok
	}
	value, ok := reader.bytes(8)
	if !ok {
		return 0, false
	}
	return uintptr(binary.LittleEndian.Uint64(value)), true
}

func etwSocketAddress(data []byte) (string, uint16) {
	if len(data) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]), 0
	}
	if len(data) < 8 {
		return "", 0
	}
	family := binary.LittleEndian.Uint16(data[:2])
	port := binary.BigEndian.Uint16(data[2:4])
	switch family {
	case 2:
		return fmt.Sprintf("%d.%d.%d.%d", data[4], data[5], data[6], data[7]), port
	case 10, 23:
		if len(data) < 24 {
			return "", 0
		}
		var address [16]byte
		copy(address[:], data[8:24])
		parsed, ok := netip.AddrFromSlice(address[:])
		if !ok {
			return "", 0
		}
		return parsed.String(), port
	default:
		// The ICMP provider has emitted a bare 16-byte IPv6 address on
		// some Windows builds rather than a SOCKADDR_IN6. Treat it as an
		// address only when the SOCKADDR family is not recognizable; this
		// keeps the parser tolerant without inventing a port.
		if len(data) == 16 {
			parsed, ok := netip.AddrFromSlice(data)
			if ok && parsed.Is6() {
				return parsed.String(), 0
			}
		}
		return "", 0
	}
}

func etwTargetCandidate(observation model.PacketObservation, scope Scope) bool {
	target := scope.Target
	expected := strings.Trim(strings.TrimSpace(target.Host), "[]")
	if address, err := netip.ParseAddr(expected); err == nil {
		expected = model.NormalizeAddr(address).String()
		for _, candidate := range []string{observation.SourceAddress, observation.DestinationAddress} {
			if strings.EqualFold(candidate, expected) {
				return true
			}
		}
		return false
	}
	// A hostname cannot be compared with the numeric addresses present in an
	// ETW event without performing a second DNS lookup. Let the correlation
	// lane use the TCP result's resolved remote tuple instead, but keep the
	// acquisition scoped to this process and requested destination port.
	if observation.Protocol == model.PacketProtocolTCP && observation.ProcessID == scope.ProcessID && target.Port != 0 &&
		(observation.SourcePort == target.Port || observation.DestinationPort == target.Port) {
		return true
	}
	return false
}

func etwTimestamp(value int64) time.Time {
	const windowsToUnix100NS = int64(11644473600 * 10000000)
	if value < windowsToUnix100NS || value > windowsToUnix100NS+int64(200*365*24*60*60*10000000) {
		return time.Time{}
	}
	nanos := (value - windowsToUnix100NS) * 100
	result := time.Unix(0, nanos).UTC()
	if result.Year() < 2000 || result.Year() > 2100 {
		return time.Time{}
	}
	return result
}

func newETWProperties(logger []uint16) (*etwProperties, []byte) {
	propertySize := int(unsafe.Sizeof(etwProperties{}))
	storage := make([]byte, propertySize+len(logger)*2)
	properties := (*etwProperties)(unsafe.Pointer(&storage[0]))
	properties.Wnode.BufferSize = uint32(len(storage))
	// Use system time so EVENT_HEADER.TimeStamp is a FILETIME value that can
	// be compared with the active probe's wall-clock window. QPC timestamps
	// would require consumer-side calibration and could not be safely matched
	// to probe timing here.
	properties.Wnode.ClientContext = 2
	properties.Wnode.Flags = etwNodeFlagTracedGUID
	properties.LogFileMode = etwRealTimeMode
	properties.BufferSize = 64
	properties.MinimumBuffers = 2
	properties.MaximumBuffers = 8
	properties.LoggerNameOffset = uint32(propertySize)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&storage[propertySize])), len(logger)), logger)
	return properties, storage
}

func etwStatusError(status uintptr, operation string) error {
	switch status {
	case errorAccessDenied, errorPrivilegeNotHeld:
		return fmt.Errorf("%w: %s returned Windows error %d", ErrInsufficientPrivilege, operation, status)
	case errorNotSupported:
		return fmt.Errorf("%w: %s returned Windows error %d", ErrUnsupported, operation, status)
	case errorInvalidParameter:
		return fmt.Errorf("%s returned Windows error %d", operation, status)
	default:
		return fmt.Errorf("%s returned Windows error %d", operation, status)
	}
}

// These layouts mirror the public ETW structures in evntrace.h. They are
// kept private so the acquisition ABI cannot become part of Tadori's report.
type etwWnodeHeader struct {
	BufferSize    uint32
	ProviderID    uint32
	Union1        uint64
	Union2        int64
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

type etwProperties struct {
	Wnode               etwWnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type etwEventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type etwEventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor etwEventDescriptor
	ProcessorTime   int64
	ActivityID      windows.GUID
}

type etwBufferContext struct {
	ProcessorIndex uint16
	LoggerID       uint16
}

type etwRecord struct {
	EventHeader       etwEventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type etwEventTraceHeader struct {
	Size      uint16
	Union1    uint16
	Union2    uint32
	ThreadID  uint32
	ProcessID uint32
	TimeStamp int64
	Union3    [16]byte
	Union4    uint64
}

type etwEventTrace struct {
	Header           etwEventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGuid       windows.GUID
	MofData          uintptr
	MofLength        uint32
	UnionCtx         uint32
}

type etwSystemTime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

type etwTimeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate etwSystemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate etwSystemTime
	DaylightBias int32
}

type etwTraceLogfileHeader struct {
	BufferSize         uint32
	VersionUnion       uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	Union1             [16]byte
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           etwTimeZoneInformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type etwLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        etwEventTrace
	LogfileHeader       etwTraceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}
