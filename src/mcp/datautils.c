#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mcp.h"
#include "spocknet.h"

//Occasionally used for debugging, just leave it here until everything matures
/*
static void ByteToHex(uint8_t *bytes, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0) printf(" ");
		printf("%02X", bytes[i]);
	}
	printf("\n");
}
*/

//TODO: write_bbuf, flush_wbuf
mcp_sbuf_t
mcp_sbuf_init(uint8_t *base, size_t len)
{
	mcp_sbuf_t sbuf;
	sbuf.base = base;
	sbuf.cur = base;
	sbuf.len = len;
	sbuf.used = 0;
	return sbuf;
}

int
mcp_write_sbuf(
__IN__  uint8_t *src, size_t len,
__OUT__ mcp_sbuf_t *sbuf
) {
	errchk((sbuf->len - sbuf->used) < len, MCP_ESBUFOVERFLOW);
	errchk(memcpy(sbuf->cur, src, len) == 0, MCP_EMEMCPY);
	sbuf->cur += len;
	sbuf->used += len;
	return len;
}

int
mcp_recv_bbuf(
	__IN__  mcp_bbuf_t *bbuf, size_t len,
	__OUT__ uint8_t *dest
) {
	errchk(bbuf->rem < len, MCP_EBBUFUNDERFLOW);
	errchk(memcpy(dest, bbuf->cur, len) == 0, MCP_EMEMCPY);
	bbuf->cur += len;
	bbuf->rem -= len;
	return len;
}

int
mcp_encode_int8(uint8_t num, mcp_sbuf_t *sbuf)
{
	return mcp_write_sbuf(&num, sizeof(num), sbuf);
}
int
mcp_decode_int8(mcp_bbuf_t *bbuf, uint8_t *num)
{
	return mcp_recv_bbuf(bbuf, sizeof(*num), num);
}

int
mcp_encode_int16(uint16_t num, mcp_sbuf_t *sbuf)
{
	uint16_t c = hton16(num);
	return mcp_write_sbuf((uint8_t*) &c, sizeof(c), sbuf);
}
int
mcp_decode_int16(mcp_bbuf_t *bbuf, uint16_t *num)
{
	int ret;
	uint16_t c;
	retchk(mcp_recv_bbuf(bbuf, sizeof(c), (uint8_t*) &c), ret);
	*num = ntoh16(c);
	return sizeof(c);
}

int
mcp_encode_int32(uint32_t num, mcp_sbuf_t *sbuf)
{
	uint32_t c = hton32(num);
	return mcp_write_sbuf((uint8_t*) &c, sizeof(c), sbuf);
}
int
mcp_decode_int32(mcp_bbuf_t *bbuf, uint32_t *num)
{
	int ret;
	uint32_t c;
	retchk(mcp_recv_bbuf(bbuf, sizeof(c), (uint8_t*) &c), ret);
	*num = ntoh32(c);
	return sizeof(c);
}

int
mcp_encode_int64(uint64_t num, mcp_sbuf_t *sbuf)
{
	uint64_t c = hton64(num);
	return mcp_write_sbuf((uint8_t*) &c, sizeof(c), sbuf);
}
int
mcp_decode_int64(mcp_bbuf_t *bbuf, uint64_t *num)
{
	int ret;
	uint64_t c;
	retchk(mcp_recv_bbuf(bbuf, sizeof(c), (uint8_t*) &c), ret);
	*num = ntoh64(c);
	return sizeof(c);
}

int
mcp_encode_float(mcp_sbuf_t *sbuf, float num)
{
	return mcp_write_sbuf((uint8_t*) &num, sizeof(num), sbuf);
}
int
mcp_decode_float(float *num, mcp_bbuf_t *bbuf)
{
	return mcp_recv_bbuf(bbuf, sizeof(*num), (uint8_t*) num);
}

int
mcp_encode_double(mcp_sbuf_t *sbuf, double num)
{
	return mcp_write_sbuf((uint8_t*) &num, sizeof(num), sbuf);
}
int
mcp_decode_double(double *num, mcp_bbuf_t *bbuf)
{
	return mcp_recv_bbuf(bbuf, sizeof(*num), (uint8_t*) num);
}

int
mcp_encode_varint(int32_t varint, mcp_sbuf_t *sbuf)
{
	uint8_t buf[sizeof(varint) + 1];
	size_t len = 0;
	for (; varint >= 0x80; ++len, varint >>= 7) {
		buf[len] = 0x80|(varint&0x7F);
	}
	buf[len] = varint&0xFF;
	++len;
	return mcp_write_sbuf(buf, len, sbuf);
}

int
mcp_decode_varint(mcp_bbuf_t *bbuf, int32_t *varint)
{
	int ret;
	size_t len = 1;
	uint8_t c;
	retchk(mcp_recv_bbuf(bbuf, sizeof(c), &c), ret);
	*varint |= (c&0x7F)<<(len*7);
	for (*varint = 0; c&0x80; ++len) {
		retchk(mcp_recv_bbuf(bbuf, sizeof(c), &c), ret);
		*varint |= (c&0x7F)<<(len*7);
	}
	return len;
}

int
mcp_encode_str(mcp_str_t str, mcp_sbuf_t *sbuf)
{
	int ret, varint_len;
	retchk(mcp_encode_varint(str.len, sbuf), ret);
	varint_len = ret;
	retchk(mcp_write_sbuf(str.base, str.len, sbuf), ret);
	return varint_len + str.len;
}

int
mcp_decode_str(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_str_t *str
) {
	int ret, varint_len;
	retchk(mcp_decode_varint(bbuf, &str->len), ret);
	varint_len = ret;
	errchk(buf_alloc(str->base, str->len) < 0, MCP_EBUFALLOC);
	retchk(mcp_recv_bbuf(bbuf, str->len, str->base), ret);
	return varint_len + str->len;
}

//All need to be update to new buffer and error system
/*
int mcp_encode_slot(uint8_t *buf, mcp_slot_t slot, size_t buf_len)
{
	if (buf_len < sizeof(slot.id)) {
		return -1;
	}
	size_t len = mcp_encode_int16(buf, slot.id);
	if (slot.id == -1) {
		return len;
	} else if (
		buf_len < len + sizeof(slot.count) + sizeof(slot.damage) +
		sizeof(slot.nbt_len) + slot.nbt_len
	) {
		return -1;
	}
	len += mcp_encode_int8(buf + len, slot.count);
	len += mcp_encode_int16(buf + len, slot.damage);
	len += mcp_encode_int16(buf + len, slot.nbt_len);
	memcpy(buf + len, slot.nbt_base, slot.nbt_len);
	len += slot.nbt_len;
	return len;
}

//ToDo: Error check mcpalloc
int mcp_decode_slot(mcp_slot_t *slot, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (buf_len < sizeof(slot->id)) {
		return -1;
	}
	size_t len = mcp_decode_int16(&slot->id, buf);
	if (slot->id == -1) {
		slot->count = -1;
		slot->damage = -1;
		slot->nbt_len = -1;
		slot->nbt_base = NULL;
		return len;
	} else if (
		buf_len < len + sizeof(slot->count) + sizeof(slot->damage) +
		sizeof(slot->nbt_len)
	) {
		return -1;
	}
	len += mcp_decode_int8(&slot->count, buf + len);
	len += mcp_decode_int16(&slot->damage, buf + len);
	len += mcp_decode_int16(&slot->nbt_len, buf + len);
	if (buf_len < len + slot->nbt_len) {
		return -1;
	}
	slot->nbt_base = mcpalloc(slot->nbt_len);
	memcpy(slot->nbt_base, buf + len, slot->nbt_len);
	len += slot->nbt_len;
	return len;
}

int mcp_encode_meta(uint8_t *buf, mcp_meta_t meta, size_t buf_len)
{
	uint8_t byte;
	size_t i, len;
	int ret;
	while (i = 0, len = 0; i < meta.len; ++i ) {
		if (buf_len < len + sizeof(uint8_t)) {
			return -1;
		}
		byte = (meta.objs[i].type_id<<5)&(meta.objs[i].index);
		len += mcp_encode_int8(buf + len, byte);
		switch (meta.objs[i].type_id) {
			case MCP_METANUM8_T:
				if (buf_len < len + sizeof(uint8_t)) {
					return -1;
				}
				len += mcp_encode_int8(buf + len, meta.objs[i].num8);
				break;
			case MCP_METANUM16_T:
				if (buf_len < len + sizeof(uint16_t)) {
					return -1;
				}
				len += mcp_encode_int16(buf + len, meta.objs[i].num16);
				break;
			case MCP_METANUM32_T:
				if (buf_len < len + sizeof(uint32_t)) {
					return -1;
				}
				len += mcp_encode_int32(buf + len, meta.objs[i].num32);
				break;
			case MCP_METANUMF_T:
				if (buf_len < len + sizeof(float)) {
					return -1;
				}
				len += mcp_encode_float(buf + len, meta.objs[i].numf);
				break;
			case MCP_METASTR_T:
				ret = mcp_encode_str(buf + len, meta.objs[i].str, buf_len);
				if (ret < 0) {
					return ret;
				}
				len += ret;
				break;
			case MCP_METASLOT_T:
				ret = mcp_encode_slot(buf + len, meta.objs[i].slot, buf_len);
				if (ret < 0) {
					return ret;
				}
				len += ret;
				break;
			case MCP_METAARR_T:
				if (buf_len < len + sizeof(uint32_t)*3) {
					return -1;
				}
				len += mcp_encode_int32(buf + len, meta.objs[i].arr[0]);
				len += mcp_encode_int32(buf + len, meta.objs[i].arr[1]);
				len += mcp_encode_int32(buf + len, meta.objs[i].arr[3]);
				break;
		}
	}
	return len;
}

int mcp_get_metasize(size_t *objs_len, uint8_t *buf, size_t buf_len)
{
	uint8_t byte;
	int ret;
	int32_t varint;
	size_t len = 0;
	(*objs_len) = 0;
	for (;;) {
		if (buf_len < len + sizeof(uint8_t)) {
			return -1;
		}
		len += mcp_decode_int8(&byte, buf + len);
		if (byte == MCP_METAEND_T) {
			return len;
		}
		switch (byte>>5) {
			case MCP_METANUM8_T:
				if (buf_len < len + sizeof(uint8_t)) {
					return -1;
				}
				len += sizeof(uint8_t);
				break;
			case MCP_METANUM16_T:
				if (buf_len < len + sizeof(uint16_t)) {
					return -1;
				}
				len += sizeof(uint16_t);
				break;
			case MCP_METANUM32_T:
				if (buf_len < len + sizeof(uint32_t)) {
					return -1;
				}
				len += sizeof(uint32_t);
				break;
			case MCP_METANUMF_T:
				if (buf_len < len + sizeof(float)) {
					return -1;
				}
				len += sizeof(float);
				break;
			case MCP_METASTR_T:
				ret = mcp_decode_varint(&varint, buf + len, buf_len);
				if (ret < 0) {
					return ret;
				} else if (buf_len < len + ret + varint) {
					return -1;
				}
				len += ret + varint;
				break;
			case MCP_METASLOT_T:
				if (buf_len < len + sizeof(uint16_t)) {
					return -1;
				}
				int16_t slot_byte;
				len += mcp_decode_int16(&slot_byte, buf + len);
				if (slot_byte == -1) {
					break;
				} else if (
					buf_len < len + sizeof(uint8_t) + sizeof(uint16_t)*2
				) {
					return -1;
				}
				len += sizeof(uint8_t) + sizeof(uint16_t);
				len += mcp_decode_int16(&slot_byte, buf + len);
				if (buf_len < len + slot_byte) {
					return -1;
				}
				len += slot_byte;
				break;
			case MCP_METAARR_T:
				if (buf_len < len + sizeof(uint32_t)*3) {
					return -1;
				}
				len += sizeof(uint32_t)*3;
				break;
		} //End of switch
		++(*objs_len);
	} //End of for loop
}

//ToDo Error check mcpalloc
int mcp_decode_meta(mcp_meta_t *meta, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	uint8_t byte;
	size_t objs_len = 0;
	int ret = mcp_get_metasize(&objs_len, buf, buf_len);
	if (ret < 0) {
		return ret;
	}
	meta->len = objs_len;
	meta->objs = mcpalloc(sizeof(mcp_metaobj_t)*objs_len);
	size_t i, len;
	for (i = 0, len = 0; i < objs_len; ++i) {
		len += mcp_decode_int8(&byte, buf);
		meta->objs[i].type_id = byte>>5;
		meta->objs[i].index = byte&0x1F;
		switch (meta->objs[i].type_id) {
			case MCP_METANUM8_T:
				len += mcp_decode_int8(&meta->objs[i].num8, buf + len);
				break;
			case MCP_METANUM16_T:
				len += mcp_decode_int16(&meta->objs[i].num16, buf + len);
				break;
			case MCP_METANUM32_T:
				len += mcp_decode_int32(&meta->objs[i].num32, buf + len);
				break;
			case MCP_METANUMF_T:
				len += mcp_decode_float(&meta->objs[i].numf, buf + len);
				break;
			case MCP_METASTR_T:
				len += mcp_decode_str(&meta->objs[i].str, buf + len, buf_len,
					mcpalloc);
				break;
			case MCP_METASLOT_T:
				len += mcp_decode_slot(&meta->objs[i].slot, buf + len, buf_len,
					mcpalloc);
				break;
			case MCP_METAARR_T:
				len += mcp_decode_int32(&meta->objs[i].arr[0], buf + len);
				len += mcp_decode_int32(&meta->objs[i].arr[1], buf + len);
				len += mcp_decode_int32(&meta->objs[i].arr[2], buf + len);
				break;
		}
	}
	return ret;
}

*/

//Does a dirty thing to send buffers, packets should really be encoded
//in their own buffer and then flushed, but this works-ish
int
mcp_encode_plen(int32_t len, mcp_sbuf_t *sbuf)
{
	int ret;
	uint8_t c[sizeof(int32_t) + 1];
	uint8_t *pbase = sbuf->cur - len;
	mcp_sbuf_t tbuf = mcp_sbuf_init(c, sizeof(int32_t) + 1);
	retchk(mcp_encode_varint(len, &tbuf), ret);
	errchk((sbuf->len - sbuf->used) < ret, MCP_ESBUFOVERFLOW);
	errchk(memmove(pbase + ret, pbase, len) == 0, MCP_EMEMCPY);
	errchk(memcpy(sbuf->cur - len, tbuf.base, ret) == 0, MCP_EMEMCPY);
	sbuf->cur += ret;
	sbuf->used += ret;
	return ret + len;
}
