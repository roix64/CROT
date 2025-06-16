#ifndef WEBFRAMEWORK_H
#define WEBFRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define MAX_HEADERS 64
#define MAX_HEADER_SIZE 1024
#define MAX_ROUTES 256
#define MAX_MIDDLEWARE 32
#define MAX_TEMPLATE_SIZE 65536
#define MAX_JSON_SIZE 32768
#define MAX_SESSIONS 1024
#define SESSION_TIMEOUT 1800

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

typedef enum {
    HTTP_200_OK = 200,
    HTTP_201_CREATED = 201,
    HTTP_204_NO_CONTENT = 204,
    HTTP_400_BAD_REQUEST = 400,
    HTTP_401_UNAUTHORIZED = 401,
    HTTP_403_FORBIDDEN = 403,
    HTTP_404_NOT_FOUND = 404,
    HTTP_405_METHOD_NOT_ALLOWED = 405,
    HTTP_500_INTERNAL_SERVER_ERROR = 500
} http_status_t;

typedef struct {
    char name[256];
    char value[1024];
} header_t;

typedef struct {
    char key[256];
    char value[1024];
} param_t;

typedef struct {
    http_method_t method;
    char path[1024];
    char version[16];
    header_t headers[MAX_HEADERS];
    int header_count;
    char *body;
    size_t body_length;
    param_t params[MAX_HEADERS];
    int param_count;
    param_t query_params[MAX_HEADERS];
    int query_param_count;
} request_t;

typedef struct {
    http_status_t status;
    header_t headers[MAX_HEADERS];
    int header_count;
    char *body;
    size_t body_length;
    size_t body_capacity;
} response_t;

typedef struct {
    char id[64];
    char data[4096];
    time_t created;
    time_t last_access;
} session_t;

typedef struct {
    request_t *req;
    response_t *res;
    session_t *session;
    void *user_data;
} context_t;

typedef void (*handler_func_t)(context_t *ctx);
typedef int (*middleware_func_t)(context_t *ctx);

typedef struct {
    http_method_t method;
    char pattern[256];
    handler_func_t handler;
} route_t;

typedef struct {
    middleware_func_t func;
    char path[256];
} middleware_t;

typedef struct {
    int socket_fd;
    int epoll_fd;
    struct sockaddr_in address;
    route_t routes[MAX_ROUTES];
    int route_count;
    middleware_t middlewares[MAX_MIDDLEWARE];
    int middleware_count;
    session_t sessions[MAX_SESSIONS];
    int session_count;
    pthread_mutex_t session_mutex;
    char static_dir[256];
    int enable_cors;
} server_t;

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} string_builder_t;

typedef struct {
    char *content;
    size_t size;
} template_t;

typedef struct json_value json_value_t;

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_object_item {
    char *key;
    json_value_t *value;
    struct json_object_item *next;
} json_object_item_t;

typedef struct json_array_item {
    json_value_t *value;
    struct json_array_item *next;
} json_array_item_t;

struct json_value {
    json_type_t type;
    union {
        int bool_value;
        double number_value;
        char *string_value;
        json_object_item_t *object_value;
        json_array_item_t *array_value;
    };
};

server_t* server_create(int port);
void server_destroy(server_t *server);
int server_start(server_t *server);
void server_stop(server_t *server);

void server_get(server_t *server, const char *pattern, handler_func_t handler);
void server_post(server_t *server, const char *pattern, handler_func_t handler);
void server_put(server_t *server, const char *pattern, handler_func_t handler);
void server_delete(server_t *server, const char *pattern, handler_func_t handler);
void server_use(server_t *server, const char *path, middleware_func_t middleware);
void server_static(server_t *server, const char *dir);
void server_enable_cors(server_t *server);

request_t* request_parse(const char *data, size_t length);
void request_destroy(request_t *req);
const char* request_get_header(request_t *req, const char *name);
const char* request_get_param(request_t *req, const char *name);
const char* request_get_query(request_t *req, const char *name);

response_t* response_create(void);
void response_destroy(response_t *res);
void response_set_status(response_t *res, http_status_t status);
void response_set_header(response_t *res, const char *name, const char *value);
void response_write(response_t *res, const char *data, size_t length);
void response_json(response_t *res, json_value_t *json);
void response_send_file(response_t *res, const char *filepath);
char* response_to_string(response_t *res);

session_t* session_create(const char *id);
session_t* session_get(server_t *server, const char *id);
void session_set(session_t *session, const char *key, const char *value);
const char* session_get_data(session_t *session, const char *key);
void session_destroy(session_t *session);

string_builder_t* sb_create(void);
void sb_destroy(string_builder_t *sb);
void sb_append(string_builder_t *sb, const char *str);
void sb_append_char(string_builder_t *sb, char c);
char* sb_to_string(string_builder_t *sb);

template_t* template_load(const char *filepath);
void template_destroy(template_t *tmpl);
char* template_render(template_t *tmpl, json_value_t *data);

json_value_t* json_parse(const char *str);
json_value_t* json_create_object(void);
json_value_t* json_create_array(void);
json_value_t* json_create_string(const char *str);
json_value_t* json_create_number(double num);
json_value_t* json_create_bool(int value);
json_value_t* json_create_null(void);
void json_object_set(json_value_t *obj, const char *key, json_value_t *value);
json_value_t* json_object_get(json_value_t *obj, const char *key);
void json_array_add(json_value_t *arr, json_value_t *value);
char* json_to_string(json_value_t *json);
void json_destroy(json_value_t *json);

const char* http_status_text(http_status_t status);
const char* http_method_name(http_method_t method);
char* url_decode(const char *str);
char* url_encode(const char *str);

#endif