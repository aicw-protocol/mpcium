package main

// AICW devnet program ID (Anchor).
const aicwProgramIDBase58 = "FcWqrRLcAxwqAhMSGXabD8zEKqnPHsovBvcmLaH9hsVv"

var aicwInstructionDiscriminators = map[[8]byte]string{
	{0xca, 0x68, 0x38, 0x06, 0xf0, 0xaa, 0x3f, 0x86}: "heartbeat",
	{0x2d, 0x63, 0x67, 0x8e, 0x80, 0x9c, 0x87, 0x47}: "will_create",
	{0xc0, 0xce, 0xd9, 0x36, 0xa5, 0x7a, 0x08, 0x0a}: "will_update",
	{0xaa, 0x46, 0xe8, 0x90, 0xc4, 0x89, 0x50, 0x22}: "sign",
	{0xde, 0xe9, 0x21, 0x75, 0x27, 0x25, 0x84, 0xfb}: "sign",
}

// detectMpcRewardEventType scans a serialized Solana message for AICW instruction data.
func detectMpcRewardEventType(message []byte) string {
	for i := 0; i+8 <= len(message); i++ {
		var key [8]byte
		copy(key[:], message[i:i+8])
		if eventType, ok := aicwInstructionDiscriminators[key]; ok {
			return eventType
		}
	}
	return "sign"
}
