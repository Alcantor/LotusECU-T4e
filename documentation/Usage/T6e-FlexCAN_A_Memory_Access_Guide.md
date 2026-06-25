### Introduction

This document describes a vendor-specific CAN protocol implemented on the Lotus Evora platform using the T6E engine control unit (ECU). The same mechanism has been observed to work across all T6E variants, including the Exige V6. It enables arbitrary memory reads and writes over the FlexCAN‑A bus for diagnostics, calibration, and development purposes. See the MPC5534 reference manual for more details about the FlexCan bus.

### FlexCAN‑A arbitrary memory access (read/write)

- **Bus**: FlexCAN‑A, standard 11‑bit identifiers
- **Unlock**: ECU must be unlocked or requests are ignored
- **Endianness**: addresses and multi‑byte values are little‑endian
- **Address windows**
  - **Reads**: 0x00000000–0x000FFFFF, 0x40000000–0x4000FFFF
  - **Writes**: 0x40000000–0x4000FFFF (alignment/size must fit within window)

### Read commands
- **0x50**: read 4 bytes at address
  - DLC = 4; Data[0..3] = address (LE)
- **0x51**: read 2 bytes at address
  - DLC = 4; Data[0..3] = address (LE)
- **0x52**: read 1 byte at address
  - DLC = 4; Data[0..3] = address (LE)
- **0x53**: read N bytes at address
  - DLC = 5 → Data[0..3] = address (LE), Data[4] = length (8‑bit)
  - DLC = 6 → Data[0..3] = address (LE), Data[4..5] = length (16‑bit, LE)

### Write commands
- **0x54**: write 4 bytes
  - DLC = 8; Data[0..3] = address (LE), Data[4..7] = value (LE)
- **0x55**: write 2 bytes
  - DLC = 6; Data[0..3] = address (LE), Data[4..5] = value (LE)
- **0x56**: write 1 byte
  - DLC = 5; Data[0..3] = address (LE), Data[4] = value
- **0x57**: stream write N bytes (N ≤ 255)
  - First frame: DLC = 5; Data[0..3] = address (LE), Data[4] = total length (8‑bit)
  - Subsequent frames: ID 0x57 with data bytes only; bytes are appended until N consumed

Notes
- Address must fall entirely within the allowed windows (address + size checked). Otherwise the read is ignored (no data response), and writes are ignored.
- Writes target RAM/register space (0x4000xxxx). Use with extreme care.

### Responses
- Reads reply on **ID 0x1E8**.
  - 0x50 → DLC 4, payload = 4 bytes at address (LE)
  - 0x51 → DLC 2
  - 0x52 → DLC 1
  - 0x53 → multiple frames as needed; each DLC = min(8, remaining)
- Writes (0x54–0x57) send no data response; verify by reading back.

### Minimal C helpers (replace I/O with your CAN stack)
```c
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
	uint32_t id;   // 11-bit standard
	uint8_t  dlc;
	uint8_t  data[8];
} can_frame_t;

bool can_send(const can_frame_t *f);
bool can_recv(can_frame_t *f, uint32_t expected_id, int timeout_ms);

static inline void pack_le32(uint8_t d[4], uint32_t v) {
	d[0]=v&0xFF; d[1]=(v>>8)&0xFF; d[2]=(v>>16)&0xFF; d[3]=(v>>24)&0xFF;
}
static inline uint32_t unpack_le32(const uint8_t d[4]) {
	return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}
static inline uint16_t unpack_le16(const uint8_t d[2]) {
	return (uint16_t)d[0] | ((uint16_t)d[1]<<8);
}
```

#### Read primitives (0x50–0x52)
```c
bool can_read32(uint32_t addr, uint32_t *out, int timeout_ms) {
	can_frame_t tx = { .id=0x050, .dlc=4 }, rx;
	pack_le32(tx.data, addr);
	if (!can_send(&tx)) return false;
	if (!can_recv(&rx, 0x1E8, timeout_ms) || rx.dlc != 4) return false;
	*out = unpack_le32(rx.data);
	return true;
}

bool can_read16(uint32_t addr, uint16_t *out, int timeout_ms) {
	can_frame_t tx = { .id=0x051, .dlc=4 }, rx;
	pack_le32(tx.data, addr);
	if (!can_send(&tx)) return false;
	if (!can_recv(&rx, 0x1E8, timeout_ms) || rx.dlc != 2) return false;
	*out = unpack_le16(rx.data);
	return true;
}

bool can_read8(uint32_t addr, uint8_t *out, int timeout_ms) {
	can_frame_t tx = { .id=0x052, .dlc=4 }, rx;
	pack_le32(tx.data, addr);
	if (!can_send(&tx)) return false;
	if (!can_recv(&rx, 0x1E8, timeout_ms) || rx.dlc != 1) return false;
	*out = rx.data[0];
	return true;
}
```

#### Read N bytes (0x53)
```c
// length can be 1..65535; ECU replies in 0..8 byte chunks on 0x1E8
bool can_readN(uint32_t addr, uint8_t *buf, uint32_t len, int timeout_ms) {
	can_frame_t tx = { .id=0x053 }, rx;
	if (len <= 0xFF) {
		tx.dlc = 5; pack_le32(tx.data, addr); tx.data[4] = (uint8_t)len;
	} else {
		tx.dlc = 6; pack_le32(tx.data, addr); tx.data[4] = (uint8_t)(len & 0xFF); tx.data[5] = (uint8_t)(len >> 8);
	}
	if (!can_send(&tx)) return false;

	uint32_t off = 0;
	while (off < len) {
		if (!can_recv(&rx, 0x1E8, timeout_ms)) return false;
		uint8_t n = rx.dlc;
		if (n == 0 || n > 8) return false;
		if (off + n > len) n = (uint8_t)(len - off);
		memcpy(buf + off, rx.data, n);
		off += n;
	}
	return true;
}
```

#### Write primitives (0x54–0x56)
```c
bool can_write32(uint32_t addr, uint32_t val) {
	can_frame_t tx = { .id=0x054, .dlc=8 };
	pack_le32(tx.data, addr);
	pack_le32(&tx.data[4], val);
	return can_send(&tx);
}

bool can_write16(uint32_t addr, uint16_t val) {
	can_frame_t tx = { .id=0x055, .dlc=6 };
	pack_le32(tx.data, addr);
	tx.data[4] = (uint8_t)(val & 0xFF);
	tx.data[5] = (uint8_t)(val >> 8);
	return can_send(&tx);
}

bool can_write8(uint32_t addr, uint8_t val) {
	can_frame_t tx = { .id=0x056, .dlc=5 };
	pack_le32(tx.data, addr);
	tx.data[4] = val;
	return can_send(&tx);
}
```

#### Stream write N bytes (0x57)
```c
// N must be ≤ 255 (8-bit length in the first frame)
bool can_write_stream(uint32_t addr, const uint8_t *buf, uint8_t len) {
	can_frame_t tx = { .id=0x057, .dlc=5 };
	pack_le32(tx.data, addr);
	tx.data[4] = len;
	if (!can_send(&tx)) return false;

	uint8_t off = 0;
	while (off < len) {
		uint8_t chunk = (uint8_t)((len - off) > 8 ? 8 : (len - off));
		tx.dlc = chunk;
		memcpy(tx.data, buf + off, chunk);
		if (!can_send(&tx)) return false;
		off += chunk;
	}
	return true;
}
```

### Examples
- Read 4 bytes at 0x40003084:
  - Send: ID 0x050, DLC 4, Data = `84 30 00 40`
  - Receive: ID 0x1E8, DLC 4, `vv vv vv vv` (LE value)
- Read 2 bytes at 0x000FF800:
  - Send: ID 0x051, DLC 4, Data = `00 F8 0F 00`
  - Receive: ID 0x1E8, DLC 2, `vv vv`
- Read 1 byte at 0x40000010:
  - Send: ID 0x052, DLC 4, Data = `10 00 00 40`
  - Receive: ID 0x1E8, DLC 1, `vv`
- Read 16 bytes at 0x000D0000:
  - Send: ID 0x053, DLC 6, Data = `00 00 0D 00 10 00`
  - Receive: two frames on 0x1E8 (DLC 8 + DLC 8) with the 16 bytes
- Write byte 0x12 to 0x4000FF00:
  - Send: ID 0x056, DLC 5, Data = `00 FF 00 40 12`
  - Verify: read back with 0x052
- Stream write 20 bytes to 0x40000080:
  - Send: ID 0x057, DLC 5, Data = `80 00 00 40 14` (0x14 = 20)
  - Then send successive 0x57 frames each carrying up to 8 data bytes until 20 sent

### Safety
- Writing to 0x4000xxxx affects live RAM/registers and can crash or damage systems. Apply only in a safe environment and verify with reads.
- Implement timeouts and validate DLCs. Out‑of‑range accesses yield no data response.
