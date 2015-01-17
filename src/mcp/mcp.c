#include <stdint.h>
#include <string.h>
#include "mcp.h"
#include "spocknet.h"

//Handshake Serverbound 0x00 Handshake
int
mcp_encode_hs00(mcp_hs00_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x00, sbuf), ret, len);
	addchk(mcp_encode_varint(packet.protocol_version, sbuf), ret, len);
	addchk(mcp_encode_str(packet.server_addr, sbuf), ret ,len);
	addchk(mcp_encode_int16(packet.server_port, sbuf), ret, len);
	addchk(mcp_encode_varint(packet.next_state, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_hs00(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_hs00_t *packet
) {
	int ret;
	size_t len = 0;
	addchk(mcp_decode_varint(bbuf, &packet->protocol_version), ret, len);
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->server_addr), ret, len);
	addchk(mcp_decode_int16(bbuf, &packet->server_port), ret, len);
	addchk(mcp_decode_varint(bbuf, &packet->next_state), ret, len);
	return len;
}

//Status Clientbound 0x00 Response
int
mcp_encode_sc00(mcp_sc00_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x00, sbuf), ret, len);
	addchk(mcp_encode_str(packet.json_response, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_sc00(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_sc00_t *packet
) {
	return mcp_decode_str(bbuf, buf_alloc, &packet->json_response);
}

//Status Clientbound 0x01 Ping
int
mcp_encode_sc01(mcp_sc01_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x01, sbuf), ret, len);
	addchk(mcp_encode_int64(packet.ping_time, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_sc01(mcp_bbuf_t *bbuf, mcp_sc01_t *packet)
{
	return mcp_decode_int64(bbuf, &packet->ping_time)
}

//Status Serverbound 0x00 Request
int
mcp_encode_ss00(mcp_ss00_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x01, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_ss00(mcp_bbuf_t *bbuf, mcp_ss00_t *packet)
{
	return 0;
}

//Login Clientbound 0x00 Disconnect
int
mcp_encode_sc00(mcp_sc00_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x00, sbuf), ret, len);
	addchk(mcp_encode_str(packet.reason, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_sc00(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_sc00_t *packet
) {
	return mcp_decode_str(bbuf, buf_alloc, &packet->reason);
}

//Login Clientbound 0x01 Encryption Request
int mcp_encode_lc01(mcp_lc01_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x01, sbuf), ret, len);
	addchk(mcp_encode_str(packet.server_id, sbuf), ret, len);
	addchk(mcp_encode_str(packet.pub_key, sbuf), ret, len);
	addchk(mcp_encode_str(packet.verify_token, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_lc01(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_lc01_t *packet
) {
	int ret;
	size_t len = 0;
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->server_id), ret, len);
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->pub_key), ret, len);
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->verify_token), ret, len);
	return len;
}

//Login Clientbound 0x02 Login Success
int mcp_encode_lc02(mcp_lc02_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x02, sbuf), ret, len);
	addchk(mcp_encode_str(packet.uuid, sbuf), ret, len);
	addchk(mcp_encode_str(packet.username, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_lc02(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_lc02_t *packet
) {
	int ret;
	size_t len = 0;
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->uuid), ret, len);
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->username), ret, len);
	return len;
}

int
mcp_encode_ls00(mcp_ls00_t packet, mcp_sbuf_t *sbuf)
{
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x00, sbuf), ret, len);
	addchk(mcp_encode_str(packet.name, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_ls00(
__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
__OUT__ mcp_ls00_t *packet
) {
	return mcp_decode_str(bbuf, buf_alloc, &packet->name);
}

//Login Serverbound 0x01 Encryption Response
int
mcp_encode_ls01(mcp_ls01_t packet, mcp_sbuf_t *sbuf) {
	int ret;
	size_t len = 0;
	addchk(mcp_encode_int8(0x01, sbuf), ret, len);
	addchk(mcp_encode_str(packet.shared_secret, sbuf), ret, len);
	addchk(mcp_encode_str(packet.verify_token, sbuf), ret, len);
	return mcp_encode_plen(len, sbuf);
}

int
mcp_decode_ls01(
	__IN__  mcp_bbuf_t *bbuf, mcp_bufalloc_cb buf_alloc,
	__OUT__ mcp_ls01_t *packet
) {
	int ret;
	size_t len = 0;
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->shared_secret), ret, len);
	addchk(mcp_decode_str(bbuf, buf_alloc, &packet->verify_token), ret, len);
	return len;
}

/*
//Play Clientbound 0x00 Keep Alive
int mcp_encode_pc00(uint8_t *buf, mcp_pc00_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf) + sizeof(packet->keep_alive)) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x00);
	len += mcp_encode_int32(buf + len, packet->keep_alive);
	return mcp_encode_plen(buf, len, buf_len);

}

int mcp_decode_pc00(mcp_pc00_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(packet->keep_alive)) {
		return -1;
	}
	mcp_decode_int32(&packet->keep_alive, buf);
	return sizeof(packet->keep_alive);
}

//Play Clientbound 0x01 Join Game
int mcp_encode_pc01(uint8_t *buf, mcp_pc01_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) +
		sizeof(packet->gamemode) + sizeof(packet->dimension) +
		sizeof(packet->difficulty) + sizeof(packet->max_players)
	) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x01);
	len += mcp_encode_int32(buf + len, packet->eid);
	len += mcp_encode_int8(buf + len, packet->gamemode);
	len += mcp_encode_int8(buf + len, packet->difficulty);
	len += mcp_encode_int8(buf + len, packet->max_players);
	int ret = mcp_encode_str(buf + len, packet->level_type, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc01(mcp_pc01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (
		buf_len < sizeof(packet->eid) + sizeof(packet->gamemode) +
		sizeof(packet->dimension) + sizeof(packet->difficulty) +
		sizeof(packet->max_players)
	) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int32(&packet->eid, buf + len);
	len += mcp_decode_int8(&packet->gamemode, buf + len);
	len += mcp_decode_int8(&packet->difficulty, buf + len);
	len += mcp_decode_int8(&packet->max_players, buf + len);
	int ret = mcp_decode_str(&packet->level_type, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

//Play Clientbound 0x02 Chat Message
int mcp_encode_pc02(uint8_t *buf, mcp_pc02_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x02);
	int ret;
	ret = mcp_encode_str(buf + sizeof(*buf), packet->json_data,
		buf_len - sizeof(*buf));
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc02(mcp_pc02_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	return mcp_decode_str(&packet->json_data, buf, buf_len, mcpalloc);
}

//Play Clientbound 0x03 Time Update
int mcp_encode_pc03(uint8_t *buf, mcp_pc03_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->age_of_world) +
		sizeof(packet->time_of_day)
	) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x03);
	len += mcp_encode_int64(buf + len, packet->age_of_world);
	len += mcp_encode_int64(buf + len, packet->time_of_day);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc03(mcp_pc03_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(packet->age_of_world) + sizeof(packet->time_of_day)) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int64(&packet->age_of_world, buf + len);
	len += mcp_decode_int64(&packet->time_of_day, buf + len);
	return len;
}

//Play Clientbound 0x04 Entity Equipment
int mcp_encode_pc04(uint8_t *buf, mcp_pc04_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) +
		sizeof(packet->slot_num)
	) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x04);
	len += mcp_encode_int32(buf + len, packet->eid);
	len += mcp_encode_int16(buf + len, packet->slot_num);
	int ret = mcp_encode_slot(buf + len, packet->item, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc04(mcp_pc04_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) +
		sizeof(packet->slot_num)
	) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int32(&packet->eid, buf + len);
	len += mcp_decode_int16(&packet->slot_num, buf + len);
	int ret = mcp_decode_slot(&packet->item, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

//Play Clientbound 0x05 Spawn Position
int mcp_encode_pc05(uint8_t *buf, mcp_pc05_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf) + sizeof(int32_t)*3) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x05);
	len += mcp_encode_int32(buf + len, packet->x);
	len += mcp_encode_int32(buf + len, packet->y);
	len += mcp_encode_int32(buf + len, packet->z);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc05(mcp_pc05_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(int32_t)*3) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int32(&packet->x, buf + len);
	len += mcp_decode_int32(&packet->y, buf + len);
	len += mcp_decode_int32(&packet->z, buf + len);
	return len;
}

//Play Clientbound 0x06 Update Health
int mcp_encode_pc06(uint8_t *buf, mcp_pc06_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->health) +
		sizeof(packet->food) + sizeof(packet->saturation)
	) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x06);
	len += mcp_encode_float(buf + len, packet->health);
	len += mcp_encode_int16(buf + len, packet->food);
	len += mcp_encode_float(buf + len, packet->saturation);
	return mcp_encode_plen(buf, len, buf_len);
}
int mcp_decode_pc06(mcp_pc06_t *packet, uint8_t *buf, size_t buf_len)
{
	if (
		buf_len < sizeof(packet->health) + sizeof(packet->food) +
		sizeof(packet->saturation)
	) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_float(&packet->health, buf + len);
	len += mcp_decode_int16(&packet->food, buf + len);
	len += mcp_decode_float(&packet->saturation, buf + len);
	return len;
}

//Play Clientbound 0x07 Respawn
int mcp_encode_pc07(uint8_t *buf, mcp_pc07_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(packet->dimension) + sizeof(packet->difficulty) +
		sizeof(packet->gamemode)
	) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x07);
	len += mcp_encode_int32(buf + len, packet->dimension);
	len += mcp_encode_int8(buf + len, packet->difficulty);
	len += mcp_encode_int8(buf + len, packet->gamemode);
	int ret = mcp_encode_str(buf + len, packet->level_type, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc07(mcp_pc07_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (
		buf_len < sizeof(packet->dimension) + sizeof(packet->difficulty) +
		sizeof(packet->gamemode)
	) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int32(&packet->dimension, buf + len);
	len += mcp_decode_int8(&packet->difficulty, buf + len);
	len += mcp_decode_int8(&packet->gamemode, buf + len);
	int ret = mcp_decode_str(&packet->level_type, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

//Play Clientbound 0x08 Player Position and Look
int mcp_encode_pc08(uint8_t *buf, mcp_pc08_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(double)*3 + sizeof(float)*2 + sizeof(uint8_t)*2) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x08);
	len += mcp_encode_double(buf + len, packet->x);
	len += mcp_encode_double(buf + len, packet->y);
	len += mcp_encode_double(buf + len, packet->z);
	len += mcp_encode_float(buf + len, packet->yaw);
	len += mcp_encode_float(buf + len, packet->pitch);
	len += mcp_encode_int8(buf + len, packet->on_ground);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc08(mcp_pc08_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(double)*3 + sizeof(float)*2 + sizeof(uint8_t)) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_double(&packet->x, buf + len);
	len += mcp_decode_double(&packet->y, buf + len);
	len += mcp_decode_double(&packet->z, buf + len);
	len += mcp_decode_float(&packet->yaw, buf + len);
	len += mcp_decode_float(&packet->pitch, buf + len);
	len += mcp_decode_int8(&packet->on_ground, buf + len);
	return len;
}

//Play Clientbound 0x09 Held Item Change
int mcp_encode_pc09(uint8_t *buf, mcp_pc09_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(uint8_t)*2) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x09);
	len += mcp_encode_int8(buf + len, packet->slot_num);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc09(mcp_pc09_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(uint8_t)) {
		return -1;
	}
	size_t len = mcp_decode_int8(&packet->slot_num, buf);
	return len;
}

//Play Clientbound 0x0A Use Bed
int mcp_encode_pc0A(uint8_t *buf, mcp_pc0A_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(int32_t)*3 + sizeof(uint8_t)*2) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x0A);
	len += mcp_encode_int32(buf + len, packet->eid);
	len += mcp_encode_int32(buf + len, packet->x);
	len += mcp_encode_int8(buf + len, packet->y);
	len += mcp_encode_int32(buf + len, packet->z);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc0A(mcp_pc0A_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(int32_t)*3 + sizeof(uint8_t)) {
		return -1;
	}
	size_t len = 0;
	len += mcp_decode_int32(&packet->eid, buf + len);
	len += mcp_decode_int32(&packet->x, buf + len);
	len += mcp_decode_int8(&packet->y, buf + len);
	len += mcp_decode_int32(&packet->z, buf + len);
	return len;
}

//Play Clientbound 0x0B Animation
int mcp_encode_pc0B(uint8_t *buf, mcp_pc0B_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(uint8_t)*2) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x0B);
	int ret = mcp_encode_varint(buf + len, packet->eid, buf_len - len);
	if (ret < 0) {
		return ret;
	} else if (buf_len < len + ret + sizeof(uint8_t)) {
		return -1;
	}
	len += ret;
	len += mcp_encode_int8(buf + len, packet->animation);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc0B(mcp_pc0B_t *packet, uint8_t *buf, size_t buf_len)
{
	size_t len = 0;
	int ret = mcp_decode_varint(&packet->eid, buf + len, buf_len - len);
	if (ret < 0) {
		return ret;
	} else if (buf_len < ret + sizeof(uint8_t)) {
		return -1;
	}
	len += ret;
	len += mcp_decode_int8(&packet->animation, buf + len);
	return len;
}

//Play Clientbound 0x0C Spawn Player
int mcp_encode_pc0C(uint8_t *buf, mcp_pc0C_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(uint8_t)) {
		return -1;
	}
	size_t len = mcp_encode_int8(buf, 0x0C);
	int ret = mcp_encode_varint(buf + len, packet->eid, buf_len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_encode_str(buf + len, packet->uuid, buf_len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_encode_str(buf + len, packet->name, buf_len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	int ret = mcp_encode_varint(buf + len, packet->data_count, buf_len);
	if (ret < 0) {
		return ret;
	}
	len += ret;

	int i;
	for (i = 0; i < packet->data_count; ++i) {
		ret = mcp_encode_str(buf + len, packet->props[i].name, buf_len);
		if (ret < 0) {
			return ret;
		}
		len += ret;
		ret = mcp_encode_str(buf + len, packet->props[i].val, buf_len);
		if (ret < 0) {
			return ret;
		}
		len += ret;
		ret = mcp_encode_str(buf + len, packet->props[i].sig, buf_len);
		if (ret < 0) {
			return ret;
		}
		len += ret;
	}

	if (buf_len < len + sizeof(int32_t)*3 + sizeof(int8_t)*2 + sizeof(int16_t)) {
		return -1;
	}
	len += mcp_encode_int32(buf + len, packet->x);
	len += mcp_encode_int32(buf + len, packet->y);
	len += mcp_encode_int32(buf + len, packet->z);
	len += mcp_encode_int16(buf + len, packet->yaw);
	len += mcp_encode_int16(buf + len, packet->pitch);
	ret = mcp_encode_meta(buf + len, packet->metadata, buf_len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

int mcp_decode_pc0C(mcp_pc0C_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	size_t len = 0;
	int ret = mcp_decode_varint(&packet->eid, buf + len, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_decode_str(&packet->uuid, buf + len, buf_len - len, mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_decode_str(&packet->name, buf + len, buf_len - len, mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;

}
*/

#undef errchk
#undef retchk
#undef addchk
#undef __IN__
#undef __OUT__
