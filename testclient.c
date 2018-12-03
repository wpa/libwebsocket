/*
    libwebsocket, an implementation of websockets version 13
    Copyright (C) 2017  alicia@ion.nu

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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "websock.h"

int main(int argc, char** argv)
{
  if(argc<3)
  {
    printf("Usage: %s <URL> <protocol>\n", argv[0]);
    return 1;
  }
  // Deconstruct URL
  char tls=!strncmp(argv[1], "wss://", 6);
  char* host=strstr(argv[1], "://");
  if(host){host=&host[3];}else{host=argv[1];}
  char* path=strchr(host, '/');
  if(path){path[0]=0; path=&path[1];}else{path="/";}
  char* port=strchr(host, ':');
  if(port){port[0]=0; port=&port[1];}else{port=(tls?"443":"80");}
  // Connect
  struct addrinfo* ai;
  if(getaddrinfo(host, port, 0, &ai)){perror("getaddrinfo"); return 1;}
  int sock=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(connect(sock, ai->ai_addr, ai->ai_addrlen)){perror("connect"); return 1;}
  freeaddrinfo(ai);
  // Initialize websocket
  websock_conn* conn=websock_new(sock, tls, 0, 0);
  if(websock_handshake_client(conn, path, host, argv[2], "https://www.websocket.org", 0))
  {
    printf("Handshake succeeded\n");
  }else{
    printf("Handshake failed\n");
    return 1;
  }
  // Poll and send/receive
  struct pollfd pfd[]={
    {.fd=0, .events=POLLIN, .revents=0},
    {.fd=sock, .events=POLLIN, .revents=0}
  };
  while(1)
  {
    poll(pfd, 2, -1);
    if(pfd[0].revents)
    {
      pfd[0].revents=0;
      char buf[2048];
      ssize_t len=read(0, buf, 2048);
      if(len<1){break;}
      websock_write(conn, buf, len, WEBSOCK_TEXT);
    }
    if(pfd[1].revents)
    {
      pfd[1].revents=0;
      struct websock_head head;
      if(!websock_readhead(conn, &head)){printf("Failed to read websocket frame head\n"); break;}
      char buf[head.length+1];
      buf[head.length]=0;
      if(!websock_readcontent(conn, buf, &head)){printf("Failed to read websocket frame\n"); break;}
      printf("Received (opcode %hhu): %s\n", head.opcode, buf);
    }
  }
  return 0;
}
