#include "webframework.h"

static volatile int running = 1;

static void signal_handler(int sig) {
    running = 0;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static char* read_file(const char *filepath, size_t *size) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *content = malloc(*size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    fread(content, 1, *size, file);
    content[*size] = '\0';
    fclose(file);
    return content;
}

static const char* get_mime_type(const char *filepath) {
    const char *ext = strrchr(filepath, '.');
    if (!ext) return "application/octet-stream";
    
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) {
        return "text/html";
    } else if (strcmp(ext, ".css") == 0) {
        return "text/css";
    } else if (strcmp(ext, ".js") == 0) {
        return "application/javascript";
    } else if (strcmp(ext, ".json") == 0) {
        return "application/json";
    } else if (strcmp(ext, ".png") == 0) {
        return "image/png";
    } else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) {
        return "image/jpeg";
    } else if (strcmp(ext, ".gif") == 0) {
        return "image/gif";
    } else if (strcmp(ext, ".svg") == 0) {
        return "image/svg+xml";
    } else if (strcmp(ext, ".pdf") == 0) {
        return "application/pdf";
    } else if (strcmp(ext, ".txt") == 0) {
        return "text/plain";
    }
    return "application/octet-stream";
}

static http_method_t parse_method(const char *method_str) {
    if (strcmp(method_str, "GET") == 0) return HTTP_GET;
    if (strcmp(method_str, "POST") == 0) return HTTP_POST;
    if (strcmp(method_str, "PUT") == 0) return HTTP_PUT;
    if (strcmp(method_str, "DELETE") == 0) return HTTP_DELETE;
    if (strcmp(method_str, "HEAD") == 0) return HTTP_HEAD;
    if (strcmp(method_str, "OPTIONS") == 0) return HTTP_OPTIONS;
    if (strcmp(method_str, "PATCH") == 0) return HTTP_PATCH;
    return HTTP_GET;
}

static void parse_query_string(const char *query, request_t *req) {
    if (!query) return;
    
    char *query_copy = strdup(query);
    char *token = strtok(query_copy, "&");
    
    while (token && req->query_param_count < MAX_HEADERS) {
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            char *decoded_key = url_decode(token);
            char *decoded_value = url_decode(eq + 1);
            
            strncpy(req->query_params[req->query_param_count].key, decoded_key, 255);
            strncpy(req->query_params[req->query_param_count].value, decoded_value, 1023);
            req->query_param_count++;
            
            free(decoded_key);
            free(decoded_value);
        }
        token = strtok(NULL, "&");
    }
    
    free(query_copy);
}

static void parse_url_params(const char *pattern, const char *path, request_t *req) {
    char pattern_copy[256], path_copy[256];
    strncpy(pattern_copy, pattern, 255);
    strncpy(path_copy, path, 255);
    
    char *pattern_token = strtok(pattern_copy, "/");
    char *path_token = strtok(path_copy, "/");
    
    while (pattern_token && path_token && req->param_count < MAX_HEADERS) {
        if (pattern_token[0] == ':') {
            strncpy(req->params[req->param_count].key, pattern_token + 1, 255);
            strncpy(req->params[req->param_count].value, path_token, 1023);
            req->param_count++;
        }
        pattern_token = strtok(NULL, "/");
        path_token = strtok(NULL, "/");
    }
}

static int match_route(const char *pattern, const char *path) {
    char pattern_copy[256], path_copy[256];
    strncpy(pattern_copy, pattern, 255);
    strncpy(path_copy, path, 255);
    
    char *pattern_token = strtok(pattern_copy, "/");
    char *path_token = strtok(path_copy, "/");
    
    while (pattern_token && path_token) {
        if (pattern_token[0] != ':' && strcmp(pattern_token, path_token) != 0) {
            return 0;
        }
        pattern_token = strtok(NULL, "/");
        path_token = strtok(NULL, "/");
    }
    
    return pattern_token == NULL && path_token == NULL;
}

static void generate_session_id(char *id, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL));
    
    for (size_t i = 0; i < size - 1; i++) {
        id[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    id[size - 1] = '\0';
}

server_t* server_create(int port) {
    server_t *server = malloc(sizeof(server_t));
    if (!server) return NULL;
    
    memset(server, 0, sizeof(server_t));
    
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd == -1) {
        free(server);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY;
    server->address.sin_port = htons(port);
    
    if (bind(server->socket_fd, (struct sockaddr*)&server->address, sizeof(server->address)) < 0) {
        close(server->socket_fd);
        free(server);
        return NULL;
    }
    
    server->epoll_fd = epoll_create1(0);
    if (server->epoll_fd == -1) {
        close(server->socket_fd);
        free(server);
        return NULL;
    }
    
    pthread_mutex_init(&server->session_mutex, NULL);
    strcpy(server->static_dir, "./static");
    
    return server;
}

void server_destroy(server_t *server) {
    if (!server) return;
    
    if (server->socket_fd != -1) close(server->socket_fd);
    if (server->epoll_fd != -1) close(server->epoll_fd);
    
    pthread_mutex_destroy(&server->session_mutex);
    free(server);
}

static void handle_static_file(context_t *ctx, const char *filepath) {
    size_t size;
    char *content = read_file(filepath, &size);
    
    if (!content) {
        response_set_status(ctx->res, HTTP_404_NOT_FOUND);
        response_write(ctx->res, "Not Found", 9);
        return;
    }
    
    const char *mime_type = get_mime_type(filepath);
    response_set_header(ctx->res, "Content-Type", mime_type);
    response_write(ctx->res, content, size);
    
    free(content);
}

static void handle_request(server_t *server, int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_read <= 0) {
        close(client_fd);
        return;
    }
    
    buffer[bytes_read] = '\0';
    
    request_t *req = request_parse(buffer, bytes_read);
    if (!req) {
        close(client_fd);
        return;
    }
    
    response_t *res = response_create();
    if (!res) {
        request_destroy(req);
        close(client_fd);
        return;
    }
    
    session_t *session = NULL;
    const char *session_id = request_get_header(req, "Cookie");
    if (session_id) {
        char *session_start = strstr(session_id, "session_id=");
        if (session_start) {
            session_start += 11;
            char *session_end = strchr(session_start, ';');
            if (session_end) {
                char session_id_str[64];
                size_t len = session_end - session_start;
                if (len < 64) {
                    strncpy(session_id_str, session_start, len);
                    session_id_str[len] = '\0';
                    session = session_get(server, session_id_str);
                }
            } else {
                session = session_get(server, session_start);
            }
        }
    }
    
    if (!session) {
        char new_session_id[64];
        generate_session_id(new_session_id, sizeof(new_session_id));
        session = session_create(new_session_id);
        
        pthread_mutex_lock(&server->session_mutex);
        if (server->session_count < MAX_SESSIONS) {
            server->sessions[server->session_count++] = *session;
        }
        pthread_mutex_unlock(&server->session_mutex);
        
        char cookie[128];
        snprintf(cookie, sizeof(cookie), "session_id=%s; Path=/; HttpOnly", new_session_id);
        response_set_header(res, "Set-Cookie", cookie);
    }
    
    context_t ctx = {
        .req = req,
        .res = res,
        .session = session,
        .user_data = NULL
    };
    
    if (server->enable_cors) {
        response_set_header(res, "Access-Control-Allow-Origin", "*");
        response_set_header(res, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response_set_header(res, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
    
    int middleware_passed = 1;
    for (int i = 0; i < server->middleware_count && middleware_passed; i++) {
        if (strlen(server->middlewares[i].path) == 0 || 
            strncmp(req->path, server->middlewares[i].path, strlen(server->middlewares[i].path)) == 0) {
            middleware_passed = server->middlewares[i].func(&ctx);
        }
    }
    
    if (middleware_passed) {
        int route_found = 0;
        
        for (int i = 0; i < server->route_count; i++) {
            if (server->routes[i].method == req->method && 
                match_route(server->routes[i].pattern, req->path)) {
                parse_url_params(server->routes[i].pattern, req->path, req);
                server->routes[i].handler(&ctx);
                route_found = 1;
                break;
            }
        }
        
        if (!route_found && req->method == HTTP_GET && strlen(server->static_dir) > 0) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s%s", server->static_dir, req->path);
            
            struct stat file_stat;
            if (stat(filepath, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                handle_static_file(&ctx, filepath);
                route_found = 1;
            }
        }
        
        if (!route_found) {
            response_set_status(res, HTTP_404_NOT_FOUND);
            response_write(res, "Not Found", 9);
        }
    }
    
    char *response_str = response_to_string(res);
    send(client_fd, response_str, strlen(response_str), 0);
    
    free(response_str);
    request_destroy(req);
    response_destroy(res);
    close(client_fd);
}

int server_start(server_t *server) {
    if (!server) return -1;
    
    if (listen(server->socket_fd, SOMAXCONN) < 0) {
        return -1;
    }
    
    set_nonblocking(server->socket_fd);
    
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server->socket_fd;
    
    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->socket_fd, &event) == -1) {
        return -1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Server listening on port %d\n", ntohs(server->address.sin_port));
    
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int event_count = epoll_wait(server->epoll_fd, events, MAX_EVENTS, 1000);
        
        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == server->socket_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &client_len);
                
                if (client_fd != -1) {
                    handle_request(server, client_fd);
                }
            }
        }
        
        pthread_mutex_lock(&server->session_mutex);
        time_t now = time(NULL);
        for (int i = 0; i < server->session_count; i++) {
            if (now - server->sessions[i].last_access > SESSION_TIMEOUT) {
                memmove(&server->sessions[i], &server->sessions[i + 1], 
                       (server->session_count - i - 1) * sizeof(session_t));
                server->session_count--;
                i--;
            }
        }
        pthread_mutex_unlock(&server->session_mutex);
    }
    
    return 0;
}

void server_stop(server_t *server) {
    running = 0;
}

void server_get(server_t *server, const char *pattern, handler_func_t handler) {
    if (!server || server->route_count >= MAX_ROUTES) return;
    
    server->routes[server->route_count].method = HTTP_GET;
    strncpy(server->routes[server->route_count].pattern, pattern, 255);
    server->routes[server->route_count].handler = handler;
    server->route_count++;
}

void server_post(server_t *server, const char *pattern, handler_func_t handler) {
    if (!server || server->route_count >= MAX_ROUTES) return;
    
    server->routes[server->route_count].method = HTTP_POST;
    strncpy(server->routes[server->route_count].pattern, pattern, 255);
    server->routes[server->route_count].handler = handler;
    server->route_count++;
}

void server_put(server_t *server, const char *pattern, handler_func_t handler) {
    if (!server || server->route_count >= MAX_ROUTES) return;
    
    server->routes[server->route_count].method = HTTP_PUT;
    strncpy(server->routes[server->route_count].pattern, pattern, 255);
    server->routes[server->route_count].handler = handler;
    server->route_count++;
}

void server_delete(server_t *server, const char *pattern, handler_func_t handler) {
    if (!server || server->route_count >= MAX_ROUTES) return;
    
    server->routes[server->route_count].method = HTTP_DELETE;
    strncpy(server->routes[server->route_count].pattern, pattern, 255);
    server->routes[server->route_count].handler = handler;
    server->route_count++;
}

void server_use(server_t *server, const char *path, middleware_func_t middleware) {
    if (!server || server->middleware_count >= MAX_MIDDLEWARE) return;
    
    server->middlewares[server->middleware_count].func = middleware;
    strncpy(server->middlewares[server->middleware_count].path, path, 255);
    server->middleware_count++;
}

void server_static(server_t *server, const char *dir) {
    if (!server) return;
    strncpy(server->static_dir, dir, 255);
}

void server_enable_cors(server_t *server) {
    if (!server) return;
    server->enable_cors = 1;
}

request_t* request_parse(const char *data, size_t length) {
    request_t *req = malloc(sizeof(request_t));
    if (!req) return NULL;
    
    memset(req, 0, sizeof(request_t));
    
    char *data_copy = malloc(length + 1);
    memcpy(data_copy, data, length);
    data_copy[length] = '\0';
    
    char *line = strtok(data_copy, "\r\n");
    if (!line) {
        free(data_copy);
        free(req);
        return NULL;
    }
    
    char method_str[16], path[1024], version[16];
    if (sscanf(line, "%15s %1023s %15s", method_str, path, version) != 3) {
        free(data_copy);
        free(req);
        return NULL;
    }
    
    req->method = parse_method(method_str);
    
    char *query = strchr(path, '?');
    if (query) {
        *query = '\0';
        query++;
        parse_query_string(query, req);
    }
    
    strncpy(req->path, path, 1023);
    strncpy(req->version, version, 15);
    
    while ((line = strtok(NULL, "\r\n")) && strlen(line) > 0) {
        if (req->header_count >= MAX_HEADERS) break;
        
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *value = colon + 1;
            while (*value == ' ') value++;
            
            strncpy(req->headers[req->header_count].name, line, 255);
            strncpy(req->headers[req->header_count].value, value, 1023);
            req->header_count++;
        }
    }
    
    const char *content_length_str = request_get_header(req, "Content-Length");
    if (content_length_str) {
        size_t content_length = atoi(content_length_str);
        if (content_length > 0) {
            char *body_start = strstr(data, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                size_t remaining = length - (body_start - data);
                if (remaining >= content_length) {
                    req->body = malloc(content_length + 1);
                    memcpy(req->body, body_start, content_length);
                    req->body[content_length] = '\0';
                    req->body_length = content_length;
                }
            }
        }
    }
    
    free(data_copy);
    return req;
}

void request_destroy(request_t *req) {
    if (!req) return;
    if (req->body) free(req->body);
    free(req);
}

const char* request_get_header(request_t *req, const char *name) {
    if (!req) return NULL;
    
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0) {
            return req->headers[i].value;
        }
    }
    return NULL;
}

const char* request_get_param(request_t *req, const char *name) {
    if (!req) return NULL;
    
    for (int i = 0; i < req->param_count; i++) {
        if (strcmp(req->params[i].key, name) == 0) {
            return req->params[i].value;
        }
    }
    return NULL;
}

const char* request_get_query(request_t *req, const char *name) {
    if (!req) return NULL;
    
    for (int i = 0; i < req->query_param_count; i++) {
        if (strcmp(req->query_params[i].key, name) == 0) {
            return req->query_params[i].value;
        }
    }
    return NULL;
}

response_t* response_create(void) {
    response_t *res = malloc(sizeof(response_t));
    if (!res) return NULL;
    
    memset(res, 0, sizeof(response_t));
    res->status = HTTP_200_OK;
    res->body_capacity = 1024;
    res->body = malloc(res->body_capacity);
    if (!res->body) {
        free(res);
        return NULL;
    }
    res->body[0] = '\0';
    
    return res;
}

void response_destroy(response_t *res) {
    if (!res) return;
    if (res->body) free(res->body);
    free(res);
}

void response_set_status(response_t *res, http_status_t status) {
    if (!res) return;
    res->status = status;
}

void response_set_header(response_t *res, const char *name, const char *value) {
    if (!res || res->header_count >= MAX_HEADERS) return;
    
    for (int i = 0; i < res->header_count; i++) {
        if (strcasecmp(res->headers[i].name, name) == 0) {
            strncpy(res->headers[i].value, value, 1023);
            return;
        }
    }
    
    strncpy(res->headers[res->header_count].name, name, 255);
    strncpy(res->headers[res->header_count].value, value, 1023);
    res->header_count++;
}

void response_write(response_t *res, const char *data, size_t length) {
    if (!res || !data) return;
    
    while (res->body_length + length >= res->body_capacity) {
        res->body_capacity *= 2;
        res->body = realloc(res->body, res->body_capacity);
        if (!res->body) return;
    }
    
    memcpy(res->body + res->body_length, data, length);
    res->body_length += length;
    res->body[res->body_length] = '\0';
}

void response_json(response_t *res, json_value_t *json) {
    if (!res || !json) return;
    
    char *json_str = json_to_string(json);
    if (json_str) {
        response_set_header(res, "Content-Type", "application/json");
        response_write(res, json_str, strlen(json_str));
        free(json_str);
    }
}

void response_send_file(response_t *res, const char *filepath) {
    if (!res || !filepath) return;
    
    size_t size;
    char *content = read_file(filepath, &size);
    
    if (!content) {
        response_set_status(res, HTTP_404_NOT_FOUND);
        response_write(res, "File not found", 14);
        return;
    }
    
    const char *mime_type = get_mime_type(filepath);
    response_set_header(res, "Content-Type", mime_type);
    response_write(res, content, size);
    
    free(content);
}

char* response_to_string(response_t *res) {
    if (!res) return NULL;
    
    string_builder_t *sb = sb_create();
    
    char status_line[64];
    snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n", 
             res->status, http_status_text(res->status));
    sb_append(sb, status_line);
    
    for (int i = 0; i < res->header_count; i++) {
        sb_append(sb, res->headers[i].name);
        sb_append(sb, ": ");
        sb_append(sb, res->headers[i].value);
        sb_append(sb, "\r\n");
    }
    
    char content_length[32];
    snprintf(content_length, sizeof(content_length), "Content-Length: %zu\r\n", res->body_length);
    sb_append(sb, content_length);
    
    sb_append(sb, "\r\n");
    
    if (res->body && res->body_length > 0) {
        for (size_t i = 0; i < res->body_length; i++) {
            sb_append_char(sb, res->body[i]);
        }
    }
    
    char *result = sb_to_string(sb);
    sb_destroy(sb);
    
    return result;
}

session_t* session_create(const char *id) {
    session_t *session = malloc(sizeof(session_t));
    if (!session) return NULL;
    
    memset(session, 0, sizeof(session_t));
    strncpy(session->id, id, 63);
    session->created = time(NULL);
    session->last_access = session->created;
    
    return session;
}

session_t* session_get(server_t *server, const char *id) {
    if (!server || !id) return NULL;
    
    pthread_mutex_lock(&server->session_mutex);
    for (int i = 0; i < server->session_count; i++) {
        if (strcmp(server->sessions[i].id, id) == 0) {
            server->sessions[i].last_access = time(NULL);
            pthread_mutex_unlock(&server->session_mutex);
            return &server->sessions[i];
        }
    }
    pthread_mutex_unlock(&server->session_mutex);
    
    return NULL;
}

void session_set(session_t *session, const char *key, const char *value) {
    if (!session || !key || !value) return;
    
    char entry[512];
    snprintf(entry, sizeof(entry), "%s=%s\n", key, value);
    
    char *existing = strstr(session->data, key);
    if (existing && (existing == session->data || existing[-1] == '\n')) {
        char *line_end = strchr(existing, '\n');
        if (line_end) {
            size_t remaining = strlen(line_end + 1);
            memmove(existing, line_end + 1, remaining + 1);
        } else {
            *existing = '\0';
        }
    }
    
    size_t current_len = strlen(session->data);
    size_t entry_len = strlen(entry);
    
    if (current_len + entry_len < sizeof(session->data) - 1) {
        strcat(session->data, entry);
    }
}

const char* session_get_data(session_t *session, const char *key) {
    if (!session || !key) return NULL;
    
    static char value[1024];
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "%s=", key);
    
    char *found = strstr(session->data, search_key);
    if (!found || (found != session->data && found[-1] != '\n')) {
        return NULL;
    }
    
    found += strlen(search_key);
    char *end = strchr(found, '\n');
    
    size_t len = end ? (size_t)(end - found) : strlen(found);
    if (len >= sizeof(value)) len = sizeof(value) - 1;
    
    strncpy(value, found, len);
    value[len] = '\0';
    
    return value;
}

void session_destroy(session_t *session) {
    if (session) free(session);
}

string_builder_t* sb_create(void) {
    string_builder_t *sb = malloc(sizeof(string_builder_t));
    if (!sb) return NULL;
    
    sb->capacity = 1024;
    sb->size = 0;
    sb->data = malloc(sb->capacity);
    if (!sb->data) {
        free(sb);
        return NULL;
    }
    sb->data[0] = '\0';
    
    return sb;
}

void sb_destroy(string_builder_t *sb) {
    if (!sb) return;
    if (sb->data) free(sb->data);
    free(sb);
}

void sb_append(string_builder_t *sb, const char *str) {
    if (!sb || !str) return;
    
    size_t len = strlen(str);
    while (sb->size + len >= sb->capacity) {
        sb->capacity *= 2;
        sb->data = realloc(sb->data, sb->capacity);
        if (!sb->data) return;
    }
    
    strcpy(sb->data + sb->size, str);
    sb->size += len;
}

void sb_append_char(string_builder_t *sb, char c) {
    if (!sb) return;
    
    if (sb->size + 1 >= sb->capacity) {
        sb->capacity *= 2;
        sb->data = realloc(sb->data, sb->capacity);
        if (!sb->data) return;
    }
    
    sb->data[sb->size] = c;
    sb->size++;
    sb->data[sb->size] = '\0';
}

char* sb_to_string(string_builder_t *sb) {
    if (!sb) return NULL;
    
    char *result = malloc(sb->size + 1);
    if (!result) return NULL;
    
    strcpy(result, sb->data);
    return result;
}

template_t* template_load(const char *filepath) {
    if (!filepath) return NULL;
    
    size_t size;
    char *content = read_file(filepath, &size);
    if (!content) return NULL;
    
    template_t *tmpl = malloc(sizeof(template_t));
    if (!tmpl) {
        free(content);
        return NULL;
    }
    
    tmpl->content = content;
    tmpl->size = size;
    
    return tmpl;
}

void template_destroy(template_t *tmpl) {
    if (!tmpl) return;
    if (tmpl->content) free(tmpl->content);
    free(tmpl);
}

static char* replace_variable(const char *template, const char *var_name, const char *value) {
    char placeholder[256];
    snprintf(placeholder, sizeof(placeholder), "{{%s}}", var_name);
    
    size_t placeholder_len = strlen(placeholder);
    size_t value_len = strlen(value);
    size_t template_len = strlen(template);
    
    char *result = malloc(template_len * 2 + value_len * 10);
    if (!result) return NULL;
    
    char *src = (char*)template;
    char *dst = result;
    
    while (*src) {
        char *found = strstr(src, placeholder);
        if (found) {
            size_t prefix_len = found - src;
            memcpy(dst, src, prefix_len);
            dst += prefix_len;
            
            strcpy(dst, value);
            dst += value_len;
            
            src = found + placeholder_len;
        } else {
            strcpy(dst, src);
            break;
        }
    }
    
    return result;
}

char* template_render(template_t *tmpl, json_value_t *data) {
    if (!tmpl || !tmpl->content) return NULL;
    
    char *result = strdup(tmpl->content);
    if (!result) return NULL;
    
    if (data && data->type == JSON_OBJECT) {
        json_object_item_t *item = data->object_value;
        while (item) {
            if (item->value && item->value->type == JSON_STRING) {
                char *new_result = replace_variable(result, item->key, item->value->string_value);
                if (new_result) {
                    free(result);
                    result = new_result;
                }
            }
            item = item->next;
        }
    }
    
    return result;
}

static void skip_whitespace(const char **str) {
    while (**str && isspace(**str)) (*str)++;
}

static json_value_t* parse_json_value(const char **str);

static json_value_t* parse_json_string(const char **str) {
    if (**str != '"') return NULL;
    (*str)++;
    
    string_builder_t *sb = sb_create();
    if (!sb) return NULL;
    
    while (**str && **str != '"') {
        if (**str == '\\') {
            (*str)++;
            switch (**str) {
                case 'n': sb_append_char(sb, '\n'); break;
                case 't': sb_append_char(sb, '\t'); break;
                case 'r': sb_append_char(sb, '\r'); break;
                case 'b': sb_append_char(sb, '\b'); break;
                case 'f': sb_append_char(sb, '\f'); break;
                case '"': sb_append_char(sb, '"'); break;
                case '\\': sb_append_char(sb, '\\'); break;
                case '/': sb_append_char(sb, '/'); break;
                default: sb_append_char(sb, **str); break;
            }
        } else {
            sb_append_char(sb, **str);
        }
        (*str)++;
    }
    
    if (**str != '"') {
        sb_destroy(sb);
        return NULL;
    }
    (*str)++;
    
    json_value_t *value = json_create_string(sb->data);
    sb_destroy(sb);
    
    return value;
}

static json_value_t* parse_json_number(const char **str) {
    char *end;
    double num = strtod(*str, &end);
    if (end == *str) return NULL;
    
    *str = end;
    return json_create_number(num);
}

static json_value_t* parse_json_object(const char **str) {
    if (**str != '{') return NULL;
    (*str)++;
    
    json_value_t *obj = json_create_object();
    if (!obj) return NULL;
    
    skip_whitespace(str);
    
    if (**str == '}') {
        (*str)++;
        return obj;
    }
    
    while (**str) {
        skip_whitespace(str);
        
        if (**str != '"') {
            json_destroy(obj);
            return NULL;
        }
        
        json_value_t *key_val = parse_json_string(str);
        if (!key_val) {
            json_destroy(obj);
            return NULL;
        }
        
        skip_whitespace(str);
        
        if (**str != ':') {
            json_destroy(key_val);
            json_destroy(obj);
            return NULL;
        }
        (*str)++;
        
        skip_whitespace(str);
        
        json_value_t *value = parse_json_value(str);
        if (!value) {
            json_destroy(key_val);
            json_destroy(obj);
            return NULL;
        }
        
        json_object_set(obj, key_val->string_value, value);
        json_destroy(key_val);
        
        skip_whitespace(str);
        
        if (**str == '}') {
            (*str)++;
            break;
        } else if (**str == ',') {
            (*str)++;
        } else {
            json_destroy(obj);
            return NULL;
        }
    }
    
    return obj;
}

static json_value_t* parse_json_array(const char **str) {
    if (**str != '[') return NULL;
    (*str)++;
    
    json_value_t *arr = json_create_array();
    if (!arr) return NULL;
    
    skip_whitespace(str);
    
    if (**str == ']') {
        (*str)++;
        return arr;
    }
    
    while (**str) {
        skip_whitespace(str);
        
        json_value_t *value = parse_json_value(str);
        if (!value) {
            json_destroy(arr);
            return NULL;
        }
        
        json_array_add(arr, value);
        
        skip_whitespace(str);
        
        if (**str == ']') {
            (*str)++;
            break;
        } else if (**str == ',') {
            (*str)++;
        } else {
            json_destroy(arr);
            return NULL;
        }
    }
    
    return arr;
}

static json_value_t* parse_json_value(const char **str) {
    skip_whitespace(str);
    
    if (**str == '"') {
        return parse_json_string(str);
    } else if (**str == '{') {
        return parse_json_object(str);
    } else if (**str == '[') {
        return parse_json_array(str);
    } else if (**str == 't' && strncmp(*str, "true", 4) == 0) {
        *str += 4;
        return json_create_bool(1);
    } else if (**str == 'f' && strncmp(*str, "false", 5) == 0) {
        *str += 5;
        return json_create_bool(0);
    } else if (**str == 'n' && strncmp(*str, "null", 4) == 0) {
        *str += 4;
        return json_create_null();
    } else if (**str == '-' || isdigit(**str)) {
        return parse_json_number(str);
    }
    
    return NULL;
}

json_value_t* json_parse(const char *str) {
    if (!str) return NULL;
    
    const char *ptr = str;
    return parse_json_value(&ptr);
}

json_value_t* json_create_object(void) {
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_OBJECT;
    value->object_value = NULL;
    
    return value;
}

json_value_t* json_create_array(void) {
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_ARRAY;
    value->array_value = NULL;
    
    return value;
}

json_value_t* json_create_string(const char *str) {
    if (!str) return NULL;
    
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_STRING;
    value->string_value = strdup(str);
    
    return value;
}

json_value_t* json_create_number(double num) {
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_NUMBER;
    value->number_value = num;
    
    return value;
}

json_value_t* json_create_bool(int val) {
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_BOOL;
    value->bool_value = val;
    
    return value;
}

json_value_t* json_create_null(void) {
    json_value_t *value = malloc(sizeof(json_value_t));
    if (!value) return NULL;
    
    value->type = JSON_NULL;
    
    return value;
}

void json_object_set(json_value_t *obj, const char *key, json_value_t *value) {
    if (!obj || obj->type != JSON_OBJECT || !key || !value) return;
    
    json_object_item_t *item = obj->object_value;
    while (item) {
        if (strcmp(item->key, key) == 0) {
            json_destroy(item->value);
            item->value = value;
            return;
        }
        item = item->next;
    }
    
    json_object_item_t *new_item = malloc(sizeof(json_object_item_t));
    if (!new_item) return;
    
    new_item->key = strdup(key);
    new_item->value = value;
    new_item->next = obj->object_value;
    obj->object_value = new_item;
}

json_value_t* json_object_get(json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT || !key) return NULL;
    
    json_object_item_t *item = obj->object_value;
    while (item) {
        if (strcmp(item->key, key) == 0) {
            return item->value;
        }
        item = item->next;
    }
    
    return NULL;
}

void json_array_add(json_value_t *arr, json_value_t *value) {
    if (!arr || arr->type != JSON_ARRAY || !value) return;
    
    json_array_item_t *new_item = malloc(sizeof(json_array_item_t));
    if (!new_item) return;
    
    new_item->value = value;
    new_item->next = arr->array_value;
    arr->array_value = new_item;
}

static void json_value_to_string(json_value_t *json, string_builder_t *sb) {
    if (!json || !sb) return;
    
    switch (json->type) {
        case JSON_NULL:
            sb_append(sb, "null");
            break;
            
        case JSON_BOOL:
            sb_append(sb, json->bool_value ? "true" : "false");
            break;
            
        case JSON_NUMBER: {
            char num_str[64];
            if (json->number_value == (long)json->number_value) {
                snprintf(num_str, sizeof(num_str), "%.0f", json->number_value);
            } else {
                snprintf(num_str, sizeof(num_str), "%g", json->number_value);
            }
            sb_append(sb, num_str);
            break;
        }
        
        case JSON_STRING:
            sb_append_char(sb, '"');
            for (const char *p = json->string_value; *p; p++) {
                switch (*p) {
                    case '"': sb_append(sb, "\\\""); break;
                    case '\\': sb_append(sb, "\\\\"); break;
                    case '\n': sb_append(sb, "\\n"); break;
                    case '\t': sb_append(sb, "\\t"); break;
                    case '\r': sb_append(sb, "\\r"); break;
                    case '\b': sb_append(sb, "\\b"); break;
                    case '\f': sb_append(sb, "\\f"); break;
                    default: sb_append_char(sb, *p); break;
                }
            }
            sb_append_char(sb, '"');
            break;
            
        case JSON_ARRAY: {
            sb_append_char(sb, '[');
            json_array_item_t *item = json->array_value;
            int first = 1;
            while (item) {
                if (!first) sb_append_char(sb, ',');
                json_value_to_string(item->value, sb);
                item = item->next;
                first = 0;
            }
            sb_append_char(sb, ']');
            break;
        }
        
        case JSON_OBJECT: {
            sb_append_char(sb, '{');
            json_object_item_t *item = json->object_value;
            int first = 1;
            while (item) {
                if (!first) sb_append_char(sb, ',');
                sb_append_char(sb, '"');
                sb_append(sb, item->key);
                sb_append(sb, "\":");
                json_value_to_string(item->value, sb);
                item = item->next;
                first = 0;
            }
            sb_append_char(sb, '}');
            break;
        }
    }
}

char* json_to_string(json_value_t *json) {
    if (!json) return NULL;
    
    string_builder_t *sb = sb_create();
    if (!sb) return NULL;
    
    json_value_to_string(json, sb);
    
    char *result = sb_to_string(sb);
    sb_destroy(sb);
    
    return result;
}

void json_destroy(json_value_t *json) {
    if (!json) return;
    
    switch (json->type) {
        case JSON_STRING:
            if (json->string_value) free(json->string_value);
            break;
            
        case JSON_ARRAY: {
            json_array_item_t *item = json->array_value;
            while (item) {
                json_array_item_t *next = item->next;
                json_destroy(item->value);
                free(item);
                item = next;
            }
            break;
        }
        
        case JSON_OBJECT: {
            json_object_item_t *item = json->object_value;
            while (item) {
                json_object_item_t *next = item->next;
                if (item->key) free(item->key);
                json_destroy(item->value);
                free(item);
                item = next;
            }
            break;
        }
        
        default:
            break;
    }
    
    free(json);
}

const char* http_status_text(http_status_t status) {
    switch (status) {
        case HTTP_200_OK: return "OK";
        case HTTP_201_CREATED: return "Created";
        case HTTP_204_NO_CONTENT: return "No Content";
        case HTTP_400_BAD_REQUEST: return "Bad Request";
        case HTTP_401_UNAUTHORIZED: return "Unauthorized";
        case HTTP_403_FORBIDDEN: return "Forbidden";
        case HTTP_404_NOT_FOUND: return "Not Found";
        case HTTP_405_METHOD_NOT_ALLOWED: return "Method Not Allowed";
        case HTTP_500_INTERNAL_SERVER_ERROR: return "Internal Server Error";
        default: return "Unknown";
    }
}

const char* http_method_name(http_method_t method) {
    switch (method) {
        case HTTP_GET: return "GET";
        case HTTP_POST: return "POST";
        case HTTP_PUT: return "PUT";
        case HTTP_DELETE: return "DELETE";
        case HTTP_HEAD: return "HEAD";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}

static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

char* url_decode(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *decoded = malloc(len + 1);
    if (!decoded) return NULL;
    
    size_t i = 0, j = 0;
    while (i < len) {
        if (str[i] == '%' && i + 2 < len) {
            int high = hex_to_int(str[i + 1]);
            int low = hex_to_int(str[i + 2]);
            if (high >= 0 && low >= 0) {
                decoded[j++] = (char)(high * 16 + low);
                i += 3;
            } else {
                decoded[j++] = str[i++];
            }
        } else if (str[i] == '+') {
            decoded[j++] = ' ';
            i++;
        } else {
            decoded[j++] = str[i++];
        }
    }
    
    decoded[j] = '\0';
    return decoded;
}

char* url_encode(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *encoded = malloc(len * 3 + 1);
    if (!encoded) return NULL;
    
    const char *hex = "0123456789ABCDEF";
    size_t j = 0;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = str[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded[j++] = c;
        } else {
            encoded[j++] = '%';
            encoded[j++] = hex[c >> 4];
            encoded[j++] = hex[c & 15];
        }
    }
    
    encoded[j] = '\0';
    return encoded;
}