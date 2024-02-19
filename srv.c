/*
srv - static http server
Matt Vianueva | gmail diatribes
*/

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/stat.h>

#ifdef __TINYC__
#define USE_OLD_REALPATH
#endif

/*-----------------------------------------------------------------------*/
/*   CONFIG                                                              */
/*-----------------------------------------------------------------------*/
#define DEFAULT_FILE "index.html"
#define DEFAULT_MIME_TYPE "application/octet-stream"
#define MIN_REQUEST_LEN 12
#define MAX_REQUEST_LEN 4096
#define MAX_HEADERS 32
#define MAX_URL_PATH 512
#define RCVTIMEO_SEC 5
#define SEND_FILE_NBYTES (size_t)(1024 * 64)
#define THREAD_STACK_SIZE (16 * 1024)

static struct config {
    char *docroot;
    size_t docroot_len;
    size_t thread_count_max;
    char *ip;
    char *port;
    char *username;
} config = {0, 0, 3000, NULL, "8080", 0};

/*-----------------------------------------------------------------------*/
/*   THREAD                                                              */
/*-----------------------------------------------------------------------*/
typedef void *(*thread_func) (void *);
static int thread_new(thread_func func, void *param);
#define thread_cond_wait(cond, mutex, expr)\
    do {\
        pthread_mutex_lock(&(mutex));\
        while (expr) {\
            pthread_cond_wait(&(cond), &(mutex));\
        }\
        pthread_cond_signal(&(cond));\
        pthread_mutex_unlock(&(mutex));\
    } while (0)

/*-----------------------------------------------------------------------*/
/*   NET                                                                 */
/*-----------------------------------------------------------------------*/
static int net_url_decode(char *url, int len,
        char **decoded_url, int *decoded_url_len);
static void net_cork(int sockfd);
static void net_uncork(int sockfd);
static ssize_t net_send_file(int sockfd, int fd);
static int net_sendbuf(int sockfd, const char *buf, size_t len);
static int net_sock_accept(int sockfd, int timeout_sec,
        struct sockaddr_storage *client);
static int net_sock_listen(const char *ip, const char *port);

/*-----------------------------------------------------------------------*/
/*   HTTP                                                                */
/*-----------------------------------------------------------------------*/
#define HTTP_METHOD_NONE 0
#define HTTP_METHOD_GET 1
#define HTTP_METHOD_HEAD 2
#define HTTP_VERSION_1_0 0
#define HTTP_VERSION_1_1 1
struct http_conn {
    int32_t fd;
    int8_t close;
    int8_t method;
    int8_t version;
    int16_t status;
    char *buf;
    char *end;
    ssize_t extra;
    char *uri;
    uint16_t urilen;
    char cip[INET_ADDRSTRLEN];
    struct headers {
        char *name, *value;
        ssize_t namelen, valuelen;
    } headers[MAX_HEADERS];
    int headers_count;
};

static void http_new_connection(int lfd);
static int http_receive_request(struct http_conn *conn);
static void http_conn_free(struct http_conn *conn);
static struct http_conn *http_conn_new(int fd);
static const char *http_status_reason(int code);
static int http_send_response(struct http_conn *conn, const char *content_type,
        size_t content_length);
static int http_send_error(struct http_conn *conn);
static int8_t http_parse_method(const char *buf);
static int http_parse_version(const char *v);
static char *http_next_token(char *p, char delim, char *end);
static char *http_next_line(char *p, char *end);
static char *http_next_eol_char(char *p, char *end);
static int http_parse_request(struct http_conn *conn);
static struct headers *http_get_header(struct http_conn *conn, char *name);
static void http_handle_headers(struct http_conn *conn);
static void http_process_request(struct http_conn *conn);
static void *http_handle_connection(void *thread_conn);
static ssize_t http_get_request_length(const char *buf, size_t len);

/*-----------------------------------------------------------------------*/
/*   MIME                                                                */
/*-----------------------------------------------------------------------*/
#define MIME_TYPE_DEFAULT DEFAULT_MIME_TYPE
#define MIME_TYPE_TEXT_HTML "text/html; charset=utf-8"
#define MIME_TYPE_TEXT_PLAIN "text/plain; charset=utf-8"
static struct mime_type {
    const char *extension;
    const char *type;
} mime_types[] = {
    {".html", MIME_TYPE_TEXT_HTML},
    {".htm",  MIME_TYPE_TEXT_HTML},
    {".txt",  MIME_TYPE_TEXT_PLAIN},
    {".c",    MIME_TYPE_TEXT_PLAIN},
    {".h",    MIME_TYPE_TEXT_PLAIN},
    {".asm",  MIME_TYPE_TEXT_PLAIN},
    {".fs" ,  MIME_TYPE_TEXT_PLAIN},
    {".vs" ,  MIME_TYPE_TEXT_PLAIN},
    {".js",   "text/javascript"},
    {".wasm" ,"application/wasm"},
    {".css" , "text/css; charset=utf-8"},
    {".xml",  "text/xml; charset=utf-8"},
    {".json", "text/json; charset=utf-8"},
    {".png",  "image/png"},
    {".jpg",  "image/jpeg"},
    {".gif",  "image/gif"},
    {NULL,    NULL}
};
static const char *get_mime_type(const char *filename);

/*-----------------------------------------------------------------------*/
/*   PATH                                                                */
/*-----------------------------------------------------------------------*/
static char *path_canonical(const char *path);
static char *path_concat(const char *path1, size_t path1len,
        const char *path2, size_t path2len);

/*-----------------------------------------------------------------------*/
/*   FILE                                                                */
/*-----------------------------------------------------------------------*/
struct file_info {
    char *path;
    struct stat statbuf;
};
static void file_info_free(struct file_info *fi);
static struct file_info *file_info_new(struct http_conn *conn);

#define strnull(s) ((s) == NULL || (s)[0] == '\0')
#define closefd(fd) do { if(fd != -1) (void)close((fd)); fd = -1; } while(0)
#define badchar(c) (((c) < ' ' && c != '\r' && c != '\n') || c == 0x7f)
#ifdef DEBUG
    #define check(x)\
    if (!(x)) {\
        if (errno) {\
            flockfile(stderr);\
            fprintf(stderr, "%s:%d " , __FILE__, __LINE__);\
            perror(NULL);\
            funlockfile(stderr);\
        }\
        errno = 0;\
        goto error;\
    }
#else
    #define check(x) if (!(x)) { errno = 0; goto error; }
#endif

#define check_msg(x, msg)\
    if (!(x)) {\
        flockfile(stderr);\
        fprintf(stderr, msg"\n");\
        funlockfile(stderr);\
        errno = 0;\
        goto error;\
    }


/*-----------------------------------------------------------------------*/
/*   VARIABLES                                                           */
/*-----------------------------------------------------------------------*/
static pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t thread_count_cond = PTHREAD_COND_INITIALIZER;
static unsigned thread_count = 0;
static unsigned most_threads = 0;

static void handle_signal(int signum)
{
    switch (signum) {
    case SIGUSR1:
    case SIGINT:
    case SIGTERM:
        syslog(LOG_INFO, "normal exit");
        printf("\n\n%u threads\n", most_threads);
        free(config.docroot);
        exit(0); 
    break;
    default:
        fprintf(stderr, "unhandled signal: %d", signum);
        break;
    }
}

/*-----------------------------------------------------------------------*/
/*   NET                                                                 */
/*-----------------------------------------------------------------------*/

/*
Decodes URL-encoded string
*/
static int net_url_decode(char *url, int len,
        char **decoded_url, int *decoded_url_len)
{
#define hex2dec(x) ((x) <= '9' ? (x) - '0' :\
                    (x) <= 'F' ? (x) - 'A' + 10 :\
                    (x) - 'a' + 10)
    char *start = NULL, *end = NULL;
    check(url);
    check(len > 0);
    start = end = calloc(len + 1, sizeof(char));
    check(start);
    while(len--) {
        if(*url == '%' && isxdigit(url[1]) && isxdigit(url[2])) {
            *end = hex2dec(url[1]) * 16 + hex2dec(url[2]);
            check(!badchar(*end));
            ++end;
            url += 3;
        } else if (*url == '+') {
            *end = ' ';
            ++end;
            ++url;
        } else {
            *end++ = *url++;
        }
    }
    *decoded_url = start;
    *decoded_url_len = end - start;
    check(decoded_url);
    check(*decoded_url_len);
    return 0;
error:
    free(start);
    decoded_url = NULL;
    return -1;
#undef hex2dec
}

/*
Cork socket, don't send partial frames, accumulate
*/
static void net_cork(int sockfd)
{
    int optval = 1;
    setsockopt(sockfd, SOL_TCP, TCP_CORK, &optval, sizeof(int));
}

/*
Uncork socket, send data
*/
static void net_uncork(int sockfd)
{
    int optval = 0;
    setsockopt(sockfd, SOL_TCP, TCP_CORK, &optval, sizeof(int));
}

/*
Send a file
*/
static ssize_t net_send_file(int sockfd, int fd)
{
    ssize_t sent = 0, n;
    char *buf = calloc(1, SEND_FILE_NBYTES);
    check(buf != NULL);
    while((n = read(fd, buf, SEND_FILE_NBYTES)) > 0) {
        check((n = write(sockfd, buf, n)) != -1);
        sent += n;
    }
    free(buf);
    return sent;

error:
    free(buf);
    return -1;
}

/*
Send a buffer
*/
static int net_sendbuf(int sockfd, const char *buf, size_t len)
{
    ssize_t sent, n;
    for (sent = n = 0; len > 0; sent += n, len -= n) {
        check((n = send(sockfd, buf, len, MSG_NOSIGNAL)) != -1);
    }
    return sent;

error:
    return -1;
}

/*
Accept and configure a tcp connection
*/
static int net_sock_accept(int sockfd, int timeout_sec,
    struct sockaddr_storage *client)
{
    int on = 1;
    int new_fd;
    struct timeval tv = {0};
    socklen_t len = sizeof(*client);

    new_fd = accept(sockfd, (struct sockaddr *)client, &len);
    check(new_fd != -1);

    tv.tv_sec = timeout_sec;
    (void)setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    (void)setsockopt(new_fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    return new_fd;

error:
    closefd(new_fd);
    return new_fd;
}

/*
Create and listen on a socket using the specified ip and port
*/
static int net_sock_listen(const char *ip, const char *port)
{
    int sockfd, on = 1;
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    check(getaddrinfo(ip, port, &hints, &res) == 0);
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    check(sockfd != -1);
    check(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != -1);
    check(bind(sockfd, res->ai_addr, res->ai_addrlen) != -1);
    check(listen(sockfd, SOMAXCONN) != -1);

    freeaddrinfo(res);
    return sockfd;

error:
    freeaddrinfo(res);
    return -1;
}

/*-----------------------------------------------------------------------*/
/*   HTTP                                                                */
/*-----------------------------------------------------------------------*/

/*
Accept a new connection, create the http connection object, launch thread
*/
static void http_new_connection(int lfd)
{
    int afd;
    struct http_conn *conn = NULL;
    struct sockaddr_storage client;

    check((afd = net_sock_accept(lfd, RCVTIMEO_SEC, &client)));
    check((conn = http_conn_new(afd)));
    inet_ntop(AF_INET, &((struct sockaddr_in *)&client)->sin_addr,
            conn->cip, sizeof(conn->cip));

    check(thread_new(http_handle_connection, conn) == 0);
    return;

error:
    http_conn_free(conn);
    closefd(afd);
    return;
}

/*
Get the length of an http request
*/
static ssize_t http_get_request_length(const char *buf, size_t len)
{
    int eol_count = 0;
    const char *end = buf + len, *p = buf;
    check(len >= MIN_REQUEST_LEN);
    for (;;) {
        check(p < end);
        if (*p == '\r') {
            check(++p < end);
            check(*p == '\n');
            ++eol_count;
        } else if (*p == '\n') {
            ++eol_count;
        } else {
            eol_count = 0;
        }
        ++p;
        if (eol_count == 2) {
            return p - buf;
        }
    }
    return 0;
error:
    return 0;
}

/*
Receive the http request into the connection object's buffer
*/
static int http_receive_request(struct http_conn *conn)
{
    ssize_t n;
    int sockfd = conn->fd;
    size_t buflen = MAX_REQUEST_LEN, reqlen = 0, total = 0;

    if (conn->extra) {
        memmove(conn->buf, conn->end + 1, conn->extra);
        total = conn->extra;
        conn->extra = 0;
        if ((reqlen = http_get_request_length(conn->buf, total)) > 0) {
            goto done;
        }
    }

    do {
        check((n = recv(sockfd, conn->buf + total, buflen - total, 0)) != -1);
        total += n;
        reqlen = http_get_request_length(conn->buf, total);
    } while (n > 0 && reqlen == 0 && total < buflen);

done:
    check(reqlen >= MIN_REQUEST_LEN);
    conn->end = conn->buf + reqlen - 1;
    conn->extra = total - reqlen;
    return 0;

error:
    conn->buf[0] = 0;
    conn->close = 1;
    return -1;
}

/*
Clean up a connection object
*/
static void http_conn_free(struct http_conn *conn)
{
    if(conn != NULL) {
        if (conn->fd != -1) {
            closefd(conn->fd);
        }
        free(conn->buf);
        free(conn);
        conn = NULL;
    }
}

/*
Create a new connection object
*/
static struct http_conn *http_conn_new(int fd)
{
    struct http_conn *conn = calloc(1, sizeof(*conn));
    check(conn);
    conn->fd = fd;
    conn->method = HTTP_METHOD_NONE;
    conn->version = HTTP_VERSION_1_0;
    conn->buf = calloc(1, MAX_REQUEST_LEN);
    conn->end = conn->buf;
    check(conn->buf);
    conn->extra = 0;
    conn->uri = NULL;
    conn->headers_count = 0;
    conn->close = 0;
    return conn;

error:
    http_conn_free(conn);
    return NULL;
}

/*
Http status code number to string lookup
*/
static const char *http_status_reason(int code)
{
    switch(code) {
    case 200:
        return "OK";
    case 400:
        return "Bad request";
    case 403:
        return "Forbidden";
    case 404:
        return "Not found";
    case 405:
        return "Method not allowed";
    case 500:
        return "Error";
    default:
        return "Error";
    }
}

/*
Send the response headers
*/
static int http_send_response(struct http_conn *conn, const char *content_type,
                              size_t content_length)
{
    const char *fmt = "HTTP/1.%c %d %s\r\n"
                      "Content-Type: %s\r\n"
                      "Content-Length: %d\r\n"
                      "Allow: GET, HEAD\r\n"
                      "Connection: %s\r\n"
                      "\r\n";
    ssize_t len;
    char *buf = NULL;
    int16_t status = conn->status;
    const char *reason = http_status_reason(status);
    char minor_version = conn->version == HTTP_VERSION_1_1 ? '1' : '0';

    len = snprintf(NULL, 0, fmt, minor_version, status, reason,
                   content_type, content_length,
                   conn->close ? "close" : "keep-alive");
    check(len > 0);
    buf = calloc(1, ++len);
    check(buf);
    len = snprintf(buf, len, fmt, minor_version, status, reason,
                   content_type, content_length,
                   conn->close ? "close" : "keep-alive");
    check(len > 0);
    check(net_sendbuf(conn->fd, buf, len) > 0);

    free(buf);
    return 0;

error:
    free(buf);
    return -1;
}

/*
Send an error message response
*/
static int http_send_error(struct http_conn *conn)
{
    const char *reason = NULL;
    size_t len = 0;

    reason = http_status_reason(conn->status);
    len = strlen(reason);
    check(http_send_response(conn, MIME_TYPE_TEXT_HTML, len) != -1);
    if (conn->method != HTTP_METHOD_HEAD) {
        check(net_sendbuf(conn->fd, reason, len) != -1);
        check(net_sendbuf(conn->fd, "\r\n", 2) != -1);
    }
    return 0;

error:
    return -1;
}

/*
Parse GET or HEAD methods
*/
static int8_t http_parse_method(const char *buf)
{
    if(buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        return HTTP_METHOD_GET;
    }
    if(buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
        return HTTP_METHOD_HEAD;
    }
    return HTTP_METHOD_NONE;
}

/*
Parse http version 1.0 or 1.1
*/
static int http_parse_version(const char *v)
{
    check(*v++ == 'H');
    check(*v++ == 'T');
    check(*v++ == 'T');
    check(*v++ == 'P');
    check(*v++ == '/');
    check(*v++ == '1');
    check(*v++ == '.');
    check(*v == '1' || *v == '0');
    return *v == '1' ? HTTP_VERSION_1_1 : HTTP_VERSION_1_0;
error:
    return -1;
}

/*
Find the next occurance of the delimter
*/
static char *http_next_token(char *p, char delim, char *end)
{
    for(;p < end && *p != delim; ++p) {
        check(!badchar(*p));
    }
    check(++p < end);
    check(!badchar(*p));
    return p;
error:
    return NULL;
}

/*
Find the next line, one character after \n
*/
static char *http_next_line(char *p, char *end)
{
    for (;p < end; ++p) {
        check(p < end);
        check(!badchar(*p));
        if (*p == '\r') {
            ++p;
            check(p < end);
            check(*p == '\n');
            break;
        } else if (*p == '\n') {
            break;
        }
    }
    check(++p < end);
    check(!badchar(*p));
    return p;
error:
    return NULL;
}

/*
Find the next end of line character, either \r or \n
*/
static char *http_next_eol_char(char *p, char *end)
{
    for (;p < end && *p != '\r' && *p != '\n' ; ++p) {
        check(!badchar(*p));
    }
    return p;
error:
    return NULL;
}

/*
Parse the request into the connection object
*/
static int http_parse_request(struct http_conn *conn)
{
    int i = 0;
    char *p, *end, *name, *val;
    p = conn->buf;
    end = conn->end;
    for(;p < end && *p == ' '; ++p);
    check((conn->method = http_parse_method(p)) != HTTP_METHOD_NONE);
    check((p = http_next_token(p, ' ', end)));
    conn->uri = p;
    check((p = http_next_token(p, ' ', end)));
    check((conn->urilen = p - conn->uri - 1) > 0);
    check((conn->version = http_parse_version(p)) != -1);
    for(i = 0; i < MAX_HEADERS && (p = http_next_line(p, end)); ++i) {
        if(*p == '\n') {
            check(p == end);
            break;
        } else if(*p == '\r') {
            check(++p == end);
            break;
        }
        name = p;
        if ((*name == ' ' || *name == '\t') && i > 0) {
            check(++name < end);
            conn->headers[i].name = "";
            conn->headers[i].namelen = 0;
            val = name;
        } else {
            check((val = http_next_token(p, ':', end)));
            conn->headers[i].name = name;
            conn->headers[i].namelen = val - name - 1;
            check(conn->headers[i].namelen > 0);
            for(; *val == ' ' || *val == '\t'; ++val) {
                check(val < end && !badchar(*val));
            }
        }
        conn->headers[i].value = val;
        check((p = http_next_eol_char(val, end)));
        conn->headers[i].valuelen = p - val;
        check(conn->headers[i].valuelen >= 0);
    }
    conn->headers_count = i;
    return 0;

error:
    return -1;
}

/*
Find an http header by name
*/
static struct headers *http_get_header(struct http_conn *conn, char *name)
{
    int i;
    struct headers *p;
    int len = strlen(name);
    for(i = 0; i < conn->headers_count; ++i) {
        p = conn->headers + i;
        if(strncasecmp(p->name, name, len < p->namelen ? len : p->namelen) == 0) {
            return p;
        }
    }
    return NULL;
}

/*
Check if the client has requested the connection to be closed
*/
static void http_handle_headers(struct http_conn *conn)
{
    struct headers *p;
    switch(conn->version) {
    case HTTP_VERSION_1_0:
        conn->close = 1;
        break;
    case HTTP_VERSION_1_1:
        if(!(p = http_get_header(conn, "connection"))) {
            break;
        }
        else if(p->valuelen != sizeof("close") - 1) {
            break;
        }
        else if(strncasecmp(p->value, "close", sizeof("close") - 1) == 0) {
            conn->close = 1;
        }
    }
}

/*
Process an http request
*/
static void http_process_request(struct http_conn *conn)
{
    int fd = -1;
    ssize_t len;
    struct file_info *fi = NULL;

    conn->status = 400;
    check(http_parse_request(conn) != -1);
    http_handle_headers(conn);
    check((fi = file_info_new(conn)));
    check((fd = open(fi->path, O_RDONLY)) != -1);

    conn->status = 200;
    len = fi->statbuf.st_size;
    check(http_send_response(conn, get_mime_type(fi->path), len) != -1);
    if (conn->method == HTTP_METHOD_GET) {
        if (net_send_file(conn->fd, fd) == -1) {
            conn->close = 1;
        }
    }
    closefd(fd);
    file_info_free(fi);
    return;

error:
    closefd(fd);
    http_send_error(conn);
    file_info_free(fi);
    conn->close = conn->status != 404;
}

/*
Add the request to the syslog
*/
static void http_add_syslog(const char *buf, ssize_t buflen)
{
    char logentry[MAX_REQUEST_LEN + 1] = {0};
    memcpy(logentry, buf, buflen);
    logentry[buflen] = 0;
    syslog(LOG_INFO, "%s", logentry);
}

/*
Handle a new http connection
*/
static void *http_handle_connection(void *thread_conn)
{
    struct http_conn *conn = (struct http_conn*)thread_conn;
    do {
        if (http_receive_request(conn) == 0) {
            http_add_syslog(conn->buf, conn->end - conn->buf);
            net_cork(conn->fd);
            http_process_request(conn);
            net_uncork(conn->fd);
        }
    } while (!conn->close);
    http_conn_free(conn);

    pthread_mutex_lock(&thread_count_mutex);
    thread_count--;
    if (thread_count < config.thread_count_max) {
        pthread_cond_signal(&thread_count_cond);
    }
    pthread_mutex_unlock(&thread_count_mutex);

    return 0;
}

/*-----------------------------------------------------------------------*/
/*   PATH                                                                */
/*-----------------------------------------------------------------------*/

/*
Get the realpath of a file
*/
static char *path_canonical(const char *path)
{
    char *resolved_path = NULL;
#ifdef USE_OLD_REALPATH
    /* for tcc */
    if(!(resolved_path = calloc(1, MAX_URL_PATH))) {
        return NULL;
    }
    if(!realpath(path, resolved_path)) {
        free(resolved_path);
        return NULL;
    }
#else
    /* other compilers */
    resolved_path = realpath(path, NULL);
#endif
    return resolved_path;
}

/*
Concatenate two file paths
*/
static char *path_concat(const char *path1, size_t path1len,
              const char *path2, size_t path2len)
{
    size_t len;
    char *p, *filepath = NULL;
    char *canonical_filepath = NULL;
    static const size_t slashlen = sizeof(char);

    len = path1len + slashlen + path2len + 1;
    check((p = filepath = calloc(1, len)));
    p = (char*)memcpy(p, path1, path1len) + path1len; *p++ = '/';
    p = (char*)memcpy(p, path2, path2len) + path2len; *p = '\0';

    canonical_filepath = path_canonical(filepath);
    check(canonical_filepath);
    free(filepath);
    filepath = NULL;

    return canonical_filepath;

error:
    free(filepath);
    free(canonical_filepath);
    return NULL;
}

/*-----------------------------------------------------------------------*/
/*   FILE                                                                */
/*-----------------------------------------------------------------------*/

/*
Clean up a file info object
*/
static void file_info_free(struct file_info *fi)
{
    if(fi != NULL) {
        free(fi->path);
        free(fi);
        fi = NULL;
    }
}

/*
Create a new file info object
*/
static struct file_info *file_info_new(struct http_conn *conn)
{
    char *dirpath = NULL;
    struct file_info *fi = NULL;
    char *decoded_uri = NULL;
    int decoded_uri_len;

    conn->status = 500;
    check((fi = calloc(1, sizeof(struct file_info))));

    conn->status = 400;
    net_url_decode(conn->uri, conn->urilen, &decoded_uri, &decoded_uri_len);
    check(decoded_uri);

    conn->status = 404;
    fi->path = path_concat(config.docroot, config.docroot_len,
            decoded_uri, decoded_uri_len);
    check(fi->path);

    if(chdir(fi->path) == 0) {
        dirpath = fi->path;
        fi->path = path_concat(dirpath, strlen(dirpath),
                DEFAULT_FILE, sizeof(DEFAULT_FILE));
        free(dirpath);
        check(fi->path);
    }
    errno = 0;
    check(stat(fi->path, &fi->statbuf) == 0);
    check(!S_ISDIR(fi->statbuf.st_mode));
    check(S_ISREG(fi->statbuf.st_mode));

    conn->status = 403;
    check(strlen(fi->path) >= config.docroot_len);
    check(memcmp(config.docroot, fi->path, config.docroot_len) == 0);
    check((fi->statbuf.st_mode & S_IRUSR));
    check((fi->statbuf.st_mode & S_IRGRP));
    check((fi->statbuf.st_mode & S_IROTH));

    free(decoded_uri);
    return fi;

error:
    free(decoded_uri);
    file_info_free(fi);
    return NULL;
}

/*-----------------------------------------------------------------------*/
/*   MIME                                                                */
/*-----------------------------------------------------------------------*/

/*
Mime type lookup
*/
static const char *get_mime_type(const char *filename)
{
    char *extension;
    struct mime_type *p;

    check(!strnull(filename));
    extension = strrchr(filename, '.');
    check(!strnull(extension));
    for (p = mime_types; p->type; ++p) {
        if (strcmp(p->extension, extension) == 0) {
            return p->type;
        }
    }
    return MIME_TYPE_DEFAULT;

error:
    return MIME_TYPE_DEFAULT;
}

/*-----------------------------------------------------------------------*/
/*   THREAD                                                              */
/*-----------------------------------------------------------------------*/

/*
Start a new thread
*/
static int thread_new(thread_func func, void *param)
{
    int rc;
    pthread_t thread_id;
    pthread_attr_t attr;
    int destroy_attr;

    destroy_attr = 0;
    rc = pthread_attr_init(&attr);
    check(rc == 0);
    destroy_attr = 1;

#ifdef THREAD_STACK_SIZE
    #if THREAD_STACK_SIZE < PTHREAD_STACK_MIN
        #error THREAD_STACK_SIZE must be >= PTHREAD_STACK_MIN
    #endif
    pthread_attr_setstacksize(&attr, (size_t)THREAD_STACK_SIZE);
#endif

    pthread_mutex_lock(&thread_count_mutex);
    thread_count++;
    if (thread_count > most_threads) {
        most_threads = thread_count;
    }
    pthread_mutex_unlock(&thread_count_mutex);

    rc = pthread_create(&thread_id, &attr, func, param);
    check(rc == 0);

    pthread_attr_destroy(&attr);
    pthread_detach(thread_id);
    return rc;

error:
    if (destroy_attr) {
        pthread_attr_destroy(&attr);
    }
    return rc;
}

static void print_usage(void)
{
    fprintf(stderr, "\nUsage: srv username port docroot [ip address]\n");
    fprintf(stderr, "e.g., srv nobody 8080 ~/docroot\n\n");
}

int main(int argc, char **argv)
{
    int lfd = -1;
    struct passwd *pw;

    if(argc < 4) {
        print_usage();
        return 0;
    }

    openlog(argv[0], LOG_NDELAY|LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "started");

    (void)signal(SIGINT, handle_signal);
    (void)signal(SIGTERM, handle_signal);
    (void)signal(SIGPIPE, SIG_IGN);
    errno = 0;

    config.username = argv[1];
    config.port = argv[2];
    config.docroot = path_canonical(argv[3]);
    if(argc == 5) {
        config.ip = argv[4];
    }

    check_msg(!strnull(config.docroot), "Invalid document root");
    config.docroot_len = strlen(config.docroot);
    check_msg(chdir(config.docroot) == 0,
            "Unable to change directory to document root");

    pw = getpwnam(config.username);
    check_msg(pw, "Failed to get uid");

    lfd = net_sock_listen(config.ip, config.port);
    check_msg(lfd != -1, "Unable to listen on port");
    check_msg(setuid(pw->pw_uid) == 0, "Failed to set uid");

    for (;;) {
        thread_cond_wait(thread_count_cond, thread_count_mutex,
                (thread_count == config.thread_count_max));
        http_new_connection(lfd);
    }
    syslog(LOG_INFO, "normal exit");
    printf("\n\n%u threads\n", most_threads);
    free(config.docroot);
    return 0;

error:
    syslog(LOG_ERR, "error exit");
    return -1;
}

