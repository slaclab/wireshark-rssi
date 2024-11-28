//////////////////////////////////////////////////////////////////////////////
// This file is part of 'wireshark-rssi'.
// It is subject to the license terms in the LICENSE.txt file found in the 
// top-level directory of this distribution and at: 
//    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html. 
// No part of 'wireshark-rssi', including this file, 
// may be copied, modified, propagated, or distributed except according to 
// the terms contained in the LICENSE.txt file.
//////////////////////////////////////////////////////////////////////////////
#include <stdint.h>
#include <stddef.h>

static inline uint16_t ones_sum(uint16_t lhs, uint16_t rhs) {
    int a = lhs + rhs;
    return (a & 0xFFFF) + (a >> 16);
}

static inline uint16_t ip_cksum(const void* data, size_t len) {
	size_t rem = len % 2;
	len /= 2;
	uint16_t s = 0;
	for (size_t i = 0; i < len; ++i)
		s = ones_sum(s, *((const uint16_t*)(data) + i));
	if (rem) {
		union { uint16_t a; uint8_t b[2]; } tb = {0};
		tb.b[0] = *(((const uint8_t*)data) + len*2);
		s = ones_sum(s, tb.a);
	}
	return ~s;
}