// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/medianexapp/go-smb2"
)

// SRVSVC RPC constants
const (
	// Named pipe for SRVSVC
	srvsvcPipe = `\PIPE\srvsvc`

	// RPC version
	rpcVersionMajor = 5
	rpcVersionMinor = 0

	// RPC packet types
	rpcRequest  = 0
	rpcResponse = 2
	rpcBind     = 11
	rpcBindAck  = 12

	// SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
	// NetrShareGetInfo operation number
	opNetrShareGetInfo = 16

	// Share info levels
	shareInfoLevel502 = 502
)

// SRVSVCClient provides access to SRVSVC RPC for share information.
type SRVSVCClient struct {
	session   *smb2.Session
	share     *smb2.Share
	pipe      *smb2.File
	callID    uint32
	contextID uint16
}

// NewSRVSVCClient creates a new SRVSVC client.
func NewSRVSVCClient(session *smb2.Session) (*SRVSVCClient, error) {
	// Connect to IPC$ share
	share, err := session.Mount("IPC$")
	if err != nil {
		return nil, fmt.Errorf("failed to mount IPC$: %w", err)
	}

	// Open the srvsvc named pipe
	pipe, err := share.OpenFile("srvsvc", 0x12019f, 0)
	if err != nil {
		share.Umount()
		return nil, fmt.Errorf("failed to open srvsvc pipe: %w", err)
	}

	client := &SRVSVCClient{
		session: session,
		share:   share,
		pipe:    pipe,
		callID:  1,
	}

	// Bind to SRVSVC interface
	if err := client.bind(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to bind to SRVSVC: %w", err)
	}

	return client, nil
}

// Close closes the SRVSVC client.
func (c *SRVSVCClient) Close() {
	if c.pipe != nil {
		c.pipe.Close()
	}
	if c.share != nil {
		c.share.Umount()
	}
}

// bind performs RPC bind to SRVSVC interface.
func (c *SRVSVCClient) bind() error {
	// SRVSVC UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
	uuid := []byte{
		0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
	}

	// Build bind request
	var buf bytes.Buffer

	// RPC header
	buf.WriteByte(rpcVersionMajor)          // Version major
	buf.WriteByte(rpcVersionMinor)          // Version minor
	buf.WriteByte(rpcBind)                  // Packet type
	buf.WriteByte(0x03)                     // Packet flags (first + last frag)
	binary.Write(&buf, binary.LittleEndian, uint32(0x10000000)) // Data representation
	binary.Write(&buf, binary.LittleEndian, uint16(72))         // Frag length
	binary.Write(&buf, binary.LittleEndian, uint16(0))          // Auth length
	binary.Write(&buf, binary.LittleEndian, c.callID)           // Call ID

	// Bind specific fields
	binary.Write(&buf, binary.LittleEndian, uint16(4280)) // Max xmit frag
	binary.Write(&buf, binary.LittleEndian, uint16(4280)) // Max recv frag
	binary.Write(&buf, binary.LittleEndian, uint32(0))    // Assoc group
	binary.Write(&buf, binary.LittleEndian, uint32(1))    // Num context items

	// Context item
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // Context ID
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // Num trans items

	// Abstract syntax (SRVSVC UUID)
	buf.Write(uuid)
	binary.Write(&buf, binary.LittleEndian, uint16(3)) // Version major
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // Version minor

	// Transfer syntax (NDR)
	ndrUUID := []byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
	buf.Write(ndrUUID)
	binary.Write(&buf, binary.LittleEndian, uint32(2)) // NDR version

	// Send bind request
	if _, err := c.pipe.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send bind request: %w", err)
	}

	// Read bind response
	response := make([]byte, 4280)
	n, err := c.pipe.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read bind response: %w", err)
	}

	if n < 24 {
		return fmt.Errorf("bind response too short")
	}

	// Check packet type
	if response[2] != rpcBindAck {
		return fmt.Errorf("unexpected response type: %d", response[2])
	}

	c.callID++
	return nil
}

// GetShareSecurityDescriptor retrieves the security descriptor for a share.
func (c *SRVSVCClient) GetShareSecurityDescriptor(serverName, shareName string) ([]byte, error) {
	// Build NetrShareGetInfo request
	var buf bytes.Buffer

	// Server name (wide string with null terminator)
	serverNameW := utf16.Encode([]rune(serverName + "\x00"))
	binary.Write(&buf, binary.LittleEndian, uint32(len(serverNameW))) // Max count
	binary.Write(&buf, binary.LittleEndian, uint32(0))                // Offset
	binary.Write(&buf, binary.LittleEndian, uint32(len(serverNameW))) // Actual count
	for _, c := range serverNameW {
		binary.Write(&buf, binary.LittleEndian, c)
	}
	// Align to 4 bytes
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}

	// Share name (wide string with null terminator)
	shareNameW := utf16.Encode([]rune(shareName + "\x00"))
	binary.Write(&buf, binary.LittleEndian, uint32(len(shareNameW))) // Max count
	binary.Write(&buf, binary.LittleEndian, uint32(0))               // Offset
	binary.Write(&buf, binary.LittleEndian, uint32(len(shareNameW))) // Actual count
	for _, c := range shareNameW {
		binary.Write(&buf, binary.LittleEndian, c)
	}
	// Align to 4 bytes
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}

	// Info level (502 for security descriptor)
	binary.Write(&buf, binary.LittleEndian, uint32(shareInfoLevel502))

	// Build RPC request
	request := c.buildRPCRequest(opNetrShareGetInfo, buf.Bytes())

	// Send request
	if _, err := c.pipe.Write(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	response := make([]byte, 65536)
	n, err := c.pipe.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	return c.parseShareInfoResponse(response[:n])
}

// buildRPCRequest builds an RPC request packet.
func (c *SRVSVCClient) buildRPCRequest(opNum uint16, data []byte) []byte {
	var buf bytes.Buffer

	fragLen := uint16(24 + len(data))

	// RPC header
	buf.WriteByte(rpcVersionMajor)          // Version major
	buf.WriteByte(rpcVersionMinor)          // Version minor
	buf.WriteByte(rpcRequest)               // Packet type
	buf.WriteByte(0x03)                     // Packet flags (first + last frag)
	binary.Write(&buf, binary.LittleEndian, uint32(0x10000000)) // Data representation
	binary.Write(&buf, binary.LittleEndian, fragLen)            // Frag length
	binary.Write(&buf, binary.LittleEndian, uint16(0))          // Auth length
	binary.Write(&buf, binary.LittleEndian, c.callID)           // Call ID

	// Request specific fields
	binary.Write(&buf, binary.LittleEndian, uint32(len(data))) // Alloc hint
	binary.Write(&buf, binary.LittleEndian, c.contextID)       // Context ID
	binary.Write(&buf, binary.LittleEndian, opNum)             // Op num

	// Data
	buf.Write(data)

	c.callID++
	return buf.Bytes()
}

// parseShareInfoResponse parses the NetrShareGetInfo response.
func (c *SRVSVCClient) parseShareInfoResponse(data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("response too short")
	}

	// Check packet type
	if data[2] != rpcResponse {
		return nil, fmt.Errorf("unexpected response type: %d", data[2])
	}

	// Skip RPC header (24 bytes)
	payload := data[24:]

	if len(payload) < 8 {
		return nil, fmt.Errorf("payload too short")
	}

	// Parse SHARE_INFO_502 structure
	// The structure contains pointers and variable-length data
	// We need to find the security descriptor offset

	// For now, return the raw payload for further parsing
	// A full implementation would parse the NDR-encoded structure

	// Check return code at the end
	if len(payload) >= 4 {
		returnCode := binary.LittleEndian.Uint32(payload[len(payload)-4:])
		if returnCode != 0 {
			return nil, fmt.Errorf("NetrShareGetInfo failed with code: 0x%08x", returnCode)
		}
	}

	// Extract security descriptor from SHARE_INFO_502
	// This requires proper NDR parsing which is complex
	// For now, we'll use a simplified approach that may not work in all cases

	return c.extractSecurityDescriptor(payload)
}

// extractSecurityDescriptor extracts the security descriptor from SHARE_INFO_502 response.
func (c *SRVSVCClient) extractSecurityDescriptor(payload []byte) ([]byte, error) {
	// SHARE_INFO_502 structure (simplified):
	// - shi502_netname (pointer)
	// - shi502_type (DWORD)
	// - shi502_remark (pointer)
	// - shi502_permissions (DWORD)
	// - shi502_max_uses (DWORD)
	// - shi502_current_uses (DWORD)
	// - shi502_path (pointer)
	// - shi502_passwd (pointer)
	// - shi502_reserved (DWORD)
	// - shi502_security_descriptor (pointer)

	// The actual data follows the structure with strings and the security descriptor

	// Look for security descriptor signature (revision byte 0x01)
	// and control flags indicating a valid SD
	for i := 0; i < len(payload)-20; i++ {
		// Check for SD revision (0x01) followed by padding (0x00)
		// and valid control flags
		if payload[i] == 0x01 && payload[i+1] == 0x00 {
			control := binary.LittleEndian.Uint16(payload[i+2:])
			// Check for common control flags (SE_DACL_PRESENT, SE_SELF_RELATIVE)
			if control&0x8004 != 0 {
				// Try to parse as security descriptor
				sd, err := ParseSecurityDescriptor(payload[i:])
				if err == nil && sd.Dacl != nil {
					// Found valid security descriptor
					// Determine length by finding the end
					sdLen := c.calculateSDLength(payload[i:])
					if sdLen > 0 && i+sdLen <= len(payload) {
						return payload[i : i+sdLen], nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("security descriptor not found in response")
}

// calculateSDLength calculates the length of a self-relative security descriptor.
func (c *SRVSVCClient) calculateSDLength(data []byte) int {
	if len(data) < 20 {
		return 0
	}

	// Self-relative SD header is 20 bytes
	// Get offsets
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	groupOffset := binary.LittleEndian.Uint32(data[8:12])
	saclOffset := binary.LittleEndian.Uint32(data[12:16])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	// Find the maximum offset and add the size of that component
	maxOffset := uint32(20) // Minimum is header size

	if ownerOffset > 0 && ownerOffset > maxOffset {
		maxOffset = ownerOffset
	}
	if groupOffset > 0 && groupOffset > maxOffset {
		maxOffset = groupOffset
	}
	if saclOffset > 0 && saclOffset > maxOffset {
		maxOffset = saclOffset
	}
	if daclOffset > 0 && daclOffset > maxOffset {
		maxOffset = daclOffset
	}

	// Add estimated size for the last component (SID or ACL)
	// This is a rough estimate - proper parsing would be more accurate
	if maxOffset > 20 && int(maxOffset) < len(data) {
		// Try to determine size based on what's at maxOffset
		remaining := data[maxOffset:]
		if len(remaining) >= 8 {
			// Could be SID or ACL
			if remaining[0] == 1 { // SID revision
				// SID: 8 + (subAuthCount * 4)
				subAuthCount := int(remaining[1])
				return int(maxOffset) + 8 + (subAuthCount * 4)
			} else if remaining[0] == 2 { // ACL revision
				// ACL: use AclSize field
				aclSize := binary.LittleEndian.Uint16(remaining[2:4])
				return int(maxOffset) + int(aclSize)
			}
		}
	}

	return int(maxOffset) + 64 // Default estimate
}
