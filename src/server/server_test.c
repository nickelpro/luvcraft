#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#include "mcp.h"

static mcp_sc00_t status_resp = {
	.json_response = {
		.base = (uint8_t *)"{\"description\":\"LUVCRAFT IS ALIVE\",\"players\":{\"max\":1,\"online\":0},\"version\":{\"name\":\"1.8\",\"protocol\":47}}",
		.len = sizeof("{\"description\":\"LUVCRAFT IS ALIVE\",\"players\":{\"max\":1,\"online\":0},\"version\":{\"name\":\"1.8\",\"protocol\":47}}") - 1
	}
};

static mcp_lc00_t lolnop = {
	.reason = {
		.base = (uint8_t *)"\"lol I'm not a real server\"",
		.len = sizeof("\"lol I'm not a real server\"") - 1
	}
};

static mcp_lc00_t proto_ver_low = {
	.reason = {
		.base = (uint8_t *)"\"Outdated client! Please use 1.8\"",
		.len = sizeof("\"Outdated client! Please use 1.8\"") - 1
	}
};

static mcp_lc00_t proto_ver_high = {
	.reason = {
		.base = (uint8_t *)"\"Outdated server! I'm still on 1.8\"",
		.len = sizeof("\"Outdated server! I'm still on 1.8\"") - 1
	}
};

typedef struct {
	uv_tcp_t tcp;
	uv_loop_t *loop;
} lvc_server_t;

typedef struct {
	uv_tcp_t tcp;
	int state;
	mcp_bbuf_t bbuf;
	int32_t read_len;
	uv_shutdown_t shutdown_req;
	lvc_server_t *server;
} lvc_client_t;

int
lvc_server_init(
	__IN__  uv_loop_t *loop,
	__OUT__ lvc_server_t *server
) {
	printf("In server init\n");
	int ret;
	retchk(uv_tcp_init(loop, &server->tcp), ret);
	server->loop = loop;
	server->tcp.data = server;
	return 0;
}

int
lvc_client_init(
	__IN__  lvc_server_t *server, uint8_t *buf, size_t buf_len,
	__OUT__ lvc_client_t *client
) {
	printf("In client init\n");
	int ret;
	retchk(uv_tcp_init(server->loop, &client->tcp), ret);
	if ((buf_len == 0)||(buf == NULL)) {
		buf_len = 4096;
		buf = malloc(buf_len);
		errchk(buf == NULL, MCP_EMALLOC);
	}
	mcp_bbuf_t *bbuf = &client->bbuf;
	bbuf->base = buf;
	bbuf->cur = buf;
	bbuf->len = buf_len;
	bbuf->used = 0;
	bbuf->rem = 0;
	client->state = 0;
	client->read_len = -1;
	client->server = server;
	client->tcp.data = client;
	return 0;
}

int
lvc_server_buf_alloc(uint8_t **base, size_t len) {
	printf("In server bufalloc, allocating: %d\n", len);
	*base = malloc(len);
	errchk(*base == NULL, MCP_EMALLOC);
	return 0;
}

void
lvc_client_bbuf_alloc(uv_handle_t *tcp, size_t size, uv_buf_t *buf)
{
	printf("In client bufalloc\n");
	lvc_client_t *client = (lvc_client_t*)tcp->data;
	mcp_bbuf_t *bbuf = &client->bbuf;
	if (
		(size > bbuf->len - bbuf->used) &&
		(size <= bbuf->len - bbuf->rem)
	) {
		memmove(bbuf->base, bbuf->cur, bbuf->rem);
		bbuf->cur = bbuf->base;
		bbuf->used = bbuf->rem;
	} else if (size > bbuf->len - bbuf->rem) {
		memmove(bbuf->base, bbuf->cur, bbuf->rem);
		bbuf->used = bbuf->rem;
		bbuf->base = realloc(bbuf->base, bbuf->used + size);
		bbuf->cur = bbuf->base;
		bbuf->len = bbuf->used + size;
	}
	*buf = uv_buf_init(
		(char*)bbuf->base + bbuf->used,
		bbuf->len - bbuf->used
	);
}

void
lvc_server_write_cb(uv_write_t *req, int status)
{
	printf("In write_cb init\n");
	free(req->data);
	free(req);
}

void
lvc_client_close_cb(uv_handle_t *tcp)
{
	printf("In client close cb\n");
	lvc_client_t *client = (lvc_client_t*)tcp->data;
	mcp_bbuf_t *client_buf = &client->bbuf;
	free(client_buf->base);
	free(client);
}

void
lvc_client_shutdown_cb(uv_shutdown_t *req, int status)
{
	printf("Shutting down a client\n");
}

void
lvc_write_disconnect(lvc_client_t *client, mcp_lc00_t packet)
{
	printf("In write disconnect\n");
	uv_write_t *req;
	uint8_t pbuf[4096];
	mcp_sbuf_t sbuf = mcp_sbuf_init(pbuf, 4096);
	int ret = mcp_encode_lc00(packet, &sbuf);
	uv_buf_t buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, lvc_server_write_cb);
}

void
lvc_write_status(lvc_client_t *client, mcp_sc00_t packet)
{
	printf("In write status\n");
	uv_write_t *req;
	uint8_t pbuf[4096];
	mcp_sbuf_t sbuf = mcp_sbuf_init(pbuf, 4096);
	int ret = mcp_encode_sc00(packet, &sbuf);
	uv_buf_t buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, lvc_server_write_cb);
}

void
lvc_write_ping(lvc_client_t *client, mcp_ss01_t packet)
{
	printf("In write ping\n");
	uv_write_t *req;
	uint8_t pbuf[4096];
	mcp_sbuf_t sbuf = mcp_sbuf_init(pbuf, 4096);
	int ret = mcp_encode_ss01(packet, &sbuf);
	uv_buf_t buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, lvc_server_write_cb);
}

void
lvc_handle_handshake(lvc_client_t *client) {
	mcp_hs00_t handshake_packet;
	if (mcp_decode_hs00(&client->bbuf, lvc_server_buf_alloc, &handshake_packet) < 0) {
		printf("Something went wrong in handshake packet decode\n");
		return;
	}
	free(handshake_packet.server_addr.base);
	client->state = handshake_packet.next_state;
	printf("Client state is: %d\n", client->state);
	if (client->state == 0x02) {
		if (handshake_packet.protocol_version == 47) {
			lvc_write_disconnect(client, lolnop);
		} else if (handshake_packet.protocol_version > 47) {
			lvc_write_disconnect(client, proto_ver_high);
		} else if (handshake_packet.protocol_version < 47) {
			lvc_write_disconnect(client, proto_ver_low);
		}
		printf("Got past write disconnect\n");
		uv_shutdown(
			&client->shutdown_req, (uv_stream_t*)&client->tcp, lvc_client_shutdown_cb
		);
	}
}

void
lvc_handle_ping(lvc_client_t *client) {
	printf("In handle ping\n");
	mcp_ss01_t ping_packet;
	if (mcp_decode_ss01(&client->bbuf, (mcp_ss01_t *) &ping_packet) < 0) {
		printf("Something went wrong in ping packet decode");
		return;
	}
	lvc_write_ping(client, ping_packet);
}

void
lvc_server_read_cb(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	printf("In read cb\n");
	lvc_client_t *client = (lvc_client_t*)tcp->data;
	mcp_bbuf_t *bbuf = &client->bbuf;

	if (nread < 0) {
		printf("Going to close\n");
		uv_close((uv_handle_t*)&client->tcp, lvc_client_close_cb);
		return;
	} else if (nread == 0) {
		return;
	}

	bbuf->used += nread;
	bbuf->rem  += nread;
	for(;;) {
		//If not waiting on a packet, decode next packet length
		if (client->read_len < 0) {
			if (mcp_decode_varint(bbuf, &client->read_len) < 0) {
				printf("Varint decode failed\n");
				//Varint decode failed, wait for more data
				client->read_len = -1;
				break;
			}
		}
		printf("Varint decode succeeded, varint is: %d\n", client->read_len);
		if (bbuf->rem < client->read_len) {
			printf("Not enough data\n");
			//Not enough data to decode packet, wait for more data
			break;
		}

		printf("Getting packet id\n");
		int32_t packet_id;
		if (mcp_decode_varint(bbuf, &packet_id) < 0) {
			//Something broke
			printf("Something has gone terribly wrong decoding packet_id");
			uv_close((uv_handle_t*)&client->tcp, lvc_client_close_cb);
			return;
		};
		printf("At switch, packet id is %d\n", packet_id);
		switch (client->state) {
			case 0x00: switch(packet_id) {
				case 0x00:
					lvc_handle_handshake(client);
					break;
				default:
					printf("Invalid packet ID for handshake: %d\n", packet_id);
					uv_close((uv_handle_t*)&client->tcp, lvc_client_close_cb);
					break;
			} break;

			case 0x01: switch(packet_id) {
				case 0x00:
					lvc_write_status(client, status_resp);
					break;
				case 0x01:
					lvc_handle_ping(client);
					break;
				default:
					printf("Invalid packet ID for status: %d\n", packet_id);
					uv_close((uv_handle_t*)&client->tcp, lvc_client_close_cb);
					break;
			} break;

			case 0x02: break;

			default:
				printf("Entered state default, something is wrong, state: %d\n",
					client->state);
				break;
		}
		client->read_len = -1;
	}
}

void
lvc_connect_cb(uv_stream_t *server_handle, int status)
{
	if (status != 0) {
		printf("Connect error %s\n", uv_err_name(status));
		return;
	}
	printf("Accepted a connection\n");
	lvc_server_t *server = server_handle->data;
	lvc_client_t *client = malloc(sizeof(*client));
	lvc_client_init(server, 0, 0, client);
	uv_accept(server_handle, (uv_stream_t*)&client->tcp);
	uv_read_start(
		(uv_stream_t*)&client->tcp, lvc_client_bbuf_alloc, lvc_server_read_cb
	);
}

int
main(int argc, char *argv[])
{
	int ret;
	printf("Running 0\n");
	struct sockaddr_in addr;
	lvc_server_t server;
	uv_ip4_addr("0.0.0.0", 8000, &addr);
	printf("Running 1\n");
	if (lvc_server_init(uv_default_loop(), &server)) {
		printf("Something has gone terribly wrong\n");
		return -1;
	}
	if (uv_tcp_bind(&server.tcp, (struct sockaddr*)&addr, 0)) {
		printf("Something has gone terribly wrong2\n");
		return -1;
	}
	ret = uv_listen((uv_stream_t*)&server.tcp, SOMAXCONN, lvc_connect_cb);
	if (ret){
		printf("Something has gone terribly wrong: %s\n", uv_err_name(ret));
		return -1;
	}
	printf("Running 2\n");
	return uv_run(server.loop, UV_RUN_DEFAULT);
}
