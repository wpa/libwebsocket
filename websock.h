/*
    libwebsocket, an implementation of websockets version 13
    Copyright (C) 2015, 2017  alicia@ion.nu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef WEBSOCK_H
#define WEBSOCK_H
#define WEBSOCK_CONT   0x0
#define WEBSOCK_TEXT   0x1
#define WEBSOCK_BINARY 0x2
#define WEBSOCK_CLOSE  0x8
#define WEBSOCK_PING   0x9
#define WEBSOCK_PONG   0xa
struct websock_head
{
// TODO: finished (last segment)?
  unsigned char opcode;
  char masked;
  unsigned char mask[4];
  unsigned long long int length;
  unsigned long long int received;
};

typedef struct websock_conn_st websock_conn;

extern websock_conn* websock_new(int fd, char tls, const char* cert, const char* key);
// NOTE: The callback decides whether or not to accept the request, and if so with which protocol, return 0/NULL to reject, nonsockcb is an option to not treat the session as a websocket session
extern char websock_handshake_server(websock_conn* conn, const char*(*cb)(const char* path, const char* host, char* protocol, const char* origin), char(*nonsockcb)(const char* path, const char* host));
extern char websock_handshake_client(websock_conn* conn, const char* path, const char* host, char* protocol, const char* origin, const char* cookie);
extern void websock_write(websock_conn* conn, const void* buf, unsigned int len, unsigned char opcode);
extern char websock_readhead(websock_conn* conn, struct websock_head* head_info);
extern char websock_readcontent(websock_conn* conn, void* buf_, struct websock_head* head);
#endif
