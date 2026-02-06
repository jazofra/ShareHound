// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"unsafe"
)

// SMB2 Info Types
const (
	SMB2_0_INFO_FILE     = 0x01
	SMB2_0_INFO_SECURITY = 0x03
)

// Security Information flags
const (
	OWNER_SECURITY_INFORMATION = 0x00000001
	GROUP_SECURITY_INFORMATION = 0x00000002
	DACL_SECURITY_INFORMATION  = 0x00000004
	SACL_SECURITY_INFORMATION  = 0x00000008
)

// QueryInfoRequest represents an SMB2 QUERY_INFO request.
// This matches the internal go-smb2 structure.
type QueryInfoRequest struct {
	InfoType              uint8
	FileInfoClass         uint8
	OutputBufferLength    uint32
	InputBufferOffset     uint16
	Reserved              uint16
	InputBufferLength     uint32
	AdditionalInformation uint32
	Flags                 uint32
	FileId                interface{}
	Input                 []byte
}

// querySecurityInfo attempts to query security info using reflection on go-smb2 File.
// This is a workaround since go-smb2 doesn't expose security descriptor queries.
func querySecurityInfo(file interface{}) ([]byte, error) {
	if file == nil {
		return nil, fmt.Errorf("file is nil")
	}

	// Get the File value using reflection
	fileVal := reflect.ValueOf(file)
	if fileVal.Kind() == reflect.Ptr {
		fileVal = fileVal.Elem()
	}

	// Check if this is the expected File type
	if fileVal.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %v", fileVal.Kind())
	}

	// Try to find and call the queryInfo method
	filePtr := reflect.ValueOf(file)

	// Look for the queryInfo method
	queryInfoMethod := filePtr.MethodByName("queryInfo")
	if !queryInfoMethod.IsValid() {
		// Method not found, try using unexported method via unsafe
		return querySecurityInfoUnsafe(file)
	}

	return nil, fmt.Errorf("queryInfo method not accessible")
}

// querySecurityInfoUnsafe uses unsafe to access unexported fields and methods.
// This is a last resort when reflection doesn't work.
func querySecurityInfoUnsafe(file interface{}) ([]byte, error) {
	// Get the *File struct
	fileVal := reflect.ValueOf(file)
	if fileVal.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("expected pointer to File")
	}
	fileElem := fileVal.Elem()

	// Get the 'fs' field (the Share)
	fsField := fileElem.FieldByName("fs")
	if !fsField.IsValid() {
		return nil, fmt.Errorf("fs field not found")
	}

	// Get the 'fd' field (the FileId)
	fdField := fileElem.FieldByName("fd")
	if !fdField.IsValid() {
		return nil, fmt.Errorf("fd field not found")
	}

	// We need to access the underlying SMB2 connection to send raw requests
	// This is complex because go-smb2 doesn't expose these internals

	// For now, return not supported - proper implementation would require
	// patching go-smb2 or using a different library
	return nil, ErrSecurityDescriptorNotSupported
}

// makeSecurityDescriptorRequest builds the raw SMB2 QUERY_INFO request bytes
// for querying security descriptors.
func makeSecurityDescriptorRequest(fileId []byte) []byte {
	// SMB2 QUERY_INFO request structure:
	// StructureSize (2) + InfoType (1) + FileInfoClass (1) +
	// OutputBufferLength (4) + InputBufferOffset (2) + Reserved (2) +
	// InputBufferLength (4) + AdditionalInformation (4) + Flags (4) +
	// FileId (16)
	buf := make([]byte, 41)

	// StructureSize = 41
	binary.LittleEndian.PutUint16(buf[0:2], 41)

	// InfoType = SMB2_0_INFO_SECURITY (3)
	buf[2] = SMB2_0_INFO_SECURITY

	// FileInfoClass = 0 (for security)
	buf[3] = 0

	// OutputBufferLength = 65536 (max size)
	binary.LittleEndian.PutUint32(buf[4:8], 65536)

	// InputBufferOffset = 0
	binary.LittleEndian.PutUint16(buf[8:10], 0)

	// Reserved = 0
	binary.LittleEndian.PutUint16(buf[10:12], 0)

	// InputBufferLength = 0
	binary.LittleEndian.PutUint32(buf[12:16], 0)

	// AdditionalInformation = OWNER | GROUP | DACL
	additionalInfo := OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	binary.LittleEndian.PutUint32(buf[16:20], uint32(additionalInfo))

	// Flags = 0
	binary.LittleEndian.PutUint32(buf[20:24], 0)

	// FileId (16 bytes)
	if len(fileId) >= 16 {
		copy(buf[24:40], fileId[:16])
	}

	return buf
}

// getFieldPointer returns a pointer to an unexported struct field.
func getFieldPointer(v reflect.Value, fieldName string) unsafe.Pointer {
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return nil
	}
	return unsafe.Pointer(field.UnsafeAddr())
}
