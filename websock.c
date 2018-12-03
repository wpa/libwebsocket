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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <glib.h>
#include "websock.h"

struct websock_conn_st
{
  char tls;
  union{
    int sock;
    gnutls_session_t session;
  };
};

static unsigned short websock_be16(unsigned short in)
{
#if(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__)
  return ((in&0xff)<<8) |
         ((in&0xff00)>>8);
#else
  return in;
#endif
}

static unsigned long long websock_be64(unsigned long long in)
{
#if(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__)
  return ((in&0xff)<<56) |
         ((in&0xff00)<<40) |
         ((in&0xff0000)<<24) |
         ((in&0xff000000)<<8) |
         ((in&0xff00000000)>>8) |
         ((in&0xff0000000000)>>24) |
         ((in&0xff000000000000)>>40) |
         ((in&0xff00000000000000)>>56);
#else
  return in;
#endif
}

// TLS/non-TLS agnostic read/write
#define awrite(conn,buf,len) (conn->tls?gnutls_record_send(conn->session, buf, len):write(conn->sock, buf, len))
#define aread(conn,buf,len) (conn->tls?gnutls_record_recv(conn->session, buf, len):read(conn->sock, buf, len))
#define awritestr(conn,buf) awrite(conn,buf,strlen(buf))

#if GNUTLS_VERSION_NUMBER<0x030109
ssize_t readwrap(void* sock, void* buf, size_t size){return read(*(int*)sock, buf, size);}
ssize_t writewrap(void* sock, const void* buf, size_t size){return write(*(int*)sock, buf, size);}
#endif

websock_conn* websock_new(int fd, char tls, const char* cert, const char* key)
{
  websock_conn* conn=malloc(sizeof(websock_conn));
  conn->tls=tls;
  if(!conn->tls){conn->sock=fd; return conn;}

  static gnutls_certificate_credentials_t cred=0;
  static gnutls_priority_t priority=0;
  if(!cred)
  {
    gnutls_global_init();
// printf("Called gnutls_global_init()\n");
    gnutls_certificate_allocate_credentials(&cred);
    if(cert && key)
    {
      if(gnutls_certificate_set_x509_key_file(cred, cert, key, GNUTLS_X509_FMT_PEM))
      {
        printf("Failed to load key files '%s' and '%s'\n", cert, key);
        free(conn);
        return 0;
      }
    }
    gnutls_priority_init(&priority, "NORMAL:%COMPAT", 0);
  }
  gnutls_init(&conn->session, (cert&&key)?GNUTLS_SERVER:GNUTLS_CLIENT);
  gnutls_priority_set(conn->session, priority);
  gnutls_credentials_set(conn->session, GNUTLS_CRD_CERTIFICATE, cred);
  gnutls_certificate_server_set_request(conn->session, GNUTLS_CERT_IGNORE); // TODO: Don't ignore for clients?
#if GNUTLS_VERSION_NUMBER<0x030109
  gnutls_transport_set_ptr(conn->session, &conn->sock);
  gnutls_transport_set_pull_function(conn->session, readwrap);
  gnutls_transport_set_push_function(conn->session, writewrap);
#else
  gnutls_transport_set_int(conn->session, fd);
#endif
  int ret;
  do{
    ret=gnutls_handshake(conn->session);
  }
  while(ret<0 && !gnutls_error_is_fatal(ret));
  if(ret<0)
  {
    printf("TLS handshake failed: %i\n", ret);
    gnutls_deinit(conn->session);
    free(conn);
    return 0;
  }
  return conn;
}

// TODO: figure out how to stop clients from re-requesting upon 400
#define WEBSOCK_BADREQ "HTTP/1.1 400 Bad Request\n" \
"Sec-WebSocket-Version: 13\n" \
"Content-length: 81\n" \
"\n" \
"<h3>Error</h3>Wrong websocket version, protocol, path, or not a websocket request"
char websock_handshake_server(websock_conn* conn, const char*(*cb)(const char* path, const char* host, char* protocol, const char* origin), char(*nonsockcb)(const char* path, const char* host))
{
  unsigned int bufsize=256;
  char* buf=malloc(bufsize);
  buf[0]=0;
  unsigned int buflen=0;
  int readlen;
  while((readlen=aread(conn, &buf[buflen], bufsize-buflen-1))>0)
  {
    buflen+=readlen;
    buf[buflen]=0;
    if(strstr(buf, "\n\n") || strstr(buf, "\r\n\r\n")){break;} // Break the loop when we received a full request
    if(buflen+256>=bufsize)
    {
      bufsize+=256;
      buf=realloc(buf, bufsize);
    }
  }
// printf("Got request:\n%s\n\n", buf);
  char* path=0;
  char* host=0;
  char* key=0;
  char* protocol=0;
  char* origin=0;

  char* line=buf;
  char* nextline;
  char firstline=1;
  unsigned int i;
  while(line[0])
  {
    while(line[0]=='\r' || line[0]=='\n'){line=&line[1];}
    for(i=0; line[i] && line[i]!='\r' && line[i]!='\n'; ++i);
    nextline=&line[i+(!!line[i])];
    line[i]=0;
    if(firstline)
    {
      firstline=0;
      if(strncmp(line, "GET ", 4)){awrite(conn, WEBSOCK_BADREQ, strlen(WEBSOCK_BADREQ)); free(buf); return 0;}
      path=&line[4];
      char* end=strchr(path, ' ');
      if(end){end[0]=0;}
      if((end=strchr(path, '\r'))){end[0]=0;}
      if((end=strchr(path, '\n'))){end[0]=0;}
    }else{
      char* colon=strchr(line, ':');
      if(colon)
      {
        colon[0]=0;
        do{colon=&colon[1];}while(colon[0]==' ');
//printf("Header: '%s', value: '%s'\n", line, colon);
        if(!strcasecmp(line, "Sec-WebSocket-Key")){key=colon;}
        else if(!strcasecmp(line, "Sec-WebSocket-Version") && strcmp(colon, "13")){awrite(conn, WEBSOCK_BADREQ, strlen(WEBSOCK_BADREQ)); free(buf); return 0;} // TODO: handle other versions maybe?
        else if(!strcasecmp(line, "Origin")){origin=colon;}
        else if(!strcasecmp(line, "Sec-WebSocket-Protocol")){protocol=colon;}
        else if(!strcasecmp(line, "Host")){host=colon;}
      }
    }
    line=nextline;
  }
  if(!key)
  {
    if(!nonsockcb || !nonsockcb(path, host))
    {
      awrite(conn, WEBSOCK_BADREQ, strlen(WEBSOCK_BADREQ));
    }
    free(buf);
    return 0;
  }
  // Check path and protocols
  const char* decidedprotocol=cb(path, host, protocol, origin);
  if(!decidedprotocol){awrite(conn, WEBSOCK_BADREQ, strlen(WEBSOCK_BADREQ)); free(buf); return 0;}
  // Hash the key+websocket HMAC
  unsigned int keylen=strlen(key);
  unsigned char keybuf[keylen+36];
  memcpy(keybuf, key, keylen);
  memcpy(&keybuf[keylen], "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
  gnutls_datum_t data;
  data.data=keybuf;
  data.size=keylen+36;
  size_t hashsize=20;
  unsigned char hashdata[hashsize];
  gnutls_fingerprint(GNUTLS_DIG_SHA1, &data, hashdata, &hashsize);
  // Base64-encode
  gchar* acceptkey=g_base64_encode((void*)hashdata, hashsize);

  awritestr(conn, "HTTP/1.1 101 Switching Protocols\r\n");
  awritestr(conn, "Upgrade: websocket\r\n");
  awritestr(conn, "Connection: Upgrade\r\n");
  awritestr(conn, "Sec-WebSocket-Accept: ");
  awritestr(conn, acceptkey);
  awritestr(conn, "\r\nSec-WebSocket-Protocol: ");
  awritestr(conn, decidedprotocol);
  awritestr(conn, "\r\n\r\n");
  g_free(acceptkey);
  free(buf); // Not freeing until here because pointing decidedprotocol to somewhere in it (e.g. the protocol header) is valid
  return 1;
}

char websock_handshake_client(websock_conn* conn, const char* path, const char* host, char* protocol, const char* origin, const char* cookie)
{
  // Generate the key
  GRand* rand=g_rand_new();
  guint32 key[4];
  key[0]=g_rand_int(rand);
  key[1]=g_rand_int(rand);
  key[2]=g_rand_int(rand);
  key[3]=g_rand_int(rand);
  g_rand_free(rand);
  gchar* key_b64=g_base64_encode((void*)key, 16);
  // Send first HTTP request, requesting websocket upgrade
  awritestr(conn, "GET "); awritestr(conn, path); awritestr(conn, " HTTP/1.1\r\n"
    "Host: "); awritestr(conn, host); awritestr(conn, "\r\n"
    "User-Agent: libwebsocket\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Origin: "); awritestr(conn, origin); awritestr(conn, "\r\n"
    "Sec-WebSocket-Protocol: "); awritestr(conn, protocol); awritestr(conn, "\r\n"
    "Sec-WebSocket-Extensions: \r\n"
    "Sec-WebSocket-Key: "); awritestr(conn, key_b64); awritestr(conn, "\r\n");
  if(cookie)
  {
    awritestr(conn, "Cookie: ");
    awritestr(conn, cookie);
    awritestr(conn, "\r\n");
  }
  awritestr(conn, "Connection: keep-alive, Upgrade\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "Upgrade: websocket\r\n"
    "\r\n");
  g_free(key_b64);
  // Read response, should have status 101 ("Switching Protocols)
  char buf[2048];
  unsigned int len=0;
  ssize_t r;
  while((r=aread(conn, &buf[len], 2047-len))>0)
  {
    len+=r;
    buf[len]=0;
    if(strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n")){break;}
  }
//  write(1, buf, len);
  if(strncmp(buf, "HTTP/1.1 101 ", 13)){printf("%s\n", buf); return 0;}
  if(!strstr(buf, "\n\n") && !strstr(buf, "\r\n\r\n")){return 0;}
  return 1; // Success
}

void websock_write(websock_conn* conn, const void* buf, unsigned int len, unsigned char opcode)
{
  unsigned char head[2];
  head[0]=0x80|opcode;
  // Handle lengths > 125
  if(len>0xffff)
  {
    head[1]=127;
  }
  else if(len>0x7e)
  {
    head[1]=126;
  }else{
    head[1]=len;
  }
//  head[1]|=0x80; // Mask
  awrite(conn, head, sizeof(unsigned char)*2);
  if((head[1]&0x7f)==126){unsigned short l=websock_be16(len); awrite(conn, &l, sizeof(l));}
  else if((head[1]&0x7f)==127){unsigned long long int l=websock_be64(len); awrite(conn, &l, sizeof(l));}
//  awrite(conn, "\x00\x00\x00\x00", 4); // The mask
// TODO: do masks on outgoing messages too?
  awrite(conn, buf, len);
}

char websock_readhead(websock_conn* conn, struct websock_head* head_info)
{
  head_info->received=0;
  uint8_t head[2];
  if(aread(conn, head, 2)!=2){return 0;}
  if(!(head[0]&0x80))
  {
printf("FIN not set! TODO: handle this scenario\n");
// TODO: handle the FIN(ished) bit if not set
  }
//  printf("headbits: %u\n", (unsigned int)(head[0]&0xf0)/16);
  head_info->opcode=head[0]&0xf;
  head_info->masked=!!(head[1]&0x80);
  head_info->length=head[1]&0x7f;
  // Handle larger length, 126=16bit, 127=64bit
  if(head_info->length==126)
  {
    unsigned short l;
    if(aread(conn, &l, sizeof(l))<1){return 0;}
    head_info->length=websock_be16(l);
  }
  else if(head_info->length==127)
  {
    if(aread(conn, &head_info->length, sizeof(head_info->length))<1){return 0;}
    head_info->length=websock_be64(head_info->length);
  }
  if(!(head[0]&0x80))
  {
printf("Non-FIN length: %llu\n", head_info->length);
  }
  if(head_info->masked)
  {
    if(aread(conn, head_info->mask, sizeof(unsigned char)*4)<sizeof(unsigned char)*4){return 0;}
  }
  return 1;
}

char websock_readcontent(websock_conn* conn, void* buf_, struct websock_head* head)
{
  if(head->length==0){return 1;} // Nothing to read, success by default
  unsigned char* buf=buf_;
  int r=aread(conn, buf+head->received, head->length-head->received);
  if(r>0)
  {
    head->received+=r;
    if(head->received<head->length){return 0;} // Not done yet
  }else{
    return 0;
  }
  if(head->masked)
  {
    unsigned int i;
    for(i=0; i<head->length; ++i)
    {
      buf[i]^=head->mask[i%4];
    }
  }
  return 1; // Got whole packet
}
