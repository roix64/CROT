#include "webframework.h"

void index_handler(context_t *ctx) {
    const char *html = 
        "<!DOCTYPE html>"
        "<html><head><title>C Web Framework</title></head>"
        "<body><h1>Welcome to C Web Framework!</h1>"
        "<p><a href='/users/123'>View User 123</a></p>"
        "<p><a href='/api/status'>API Status</a></p>"
        "</body></html>";
    
    response_set_header(ctx->res, "Content-Type", "text/html");
    response_write(ctx->res, html, strlen(html));
}

void user_handler(context_t *ctx) {
    const char *user_id = request_get_param(ctx->req, "id");
    if (user_id) {
        json_value_t *response = json_create_object();
        json_object_set(response, "user_id", json_create_string(user_id));
        json_object_set(response, "name", json_create_string("John Doe"));
        json_object_set(response, "email", json_create_string("john@example.com"));
        
        response_json(ctx->res, response);
        json_destroy(response);
    } else {
        response_set_status(ctx->res, HTTP_400_BAD_REQUEST);
        response_write(ctx->res, "User ID required", 16);
    }
}

void api_status_handler(context_t *ctx) {
    json_value_t *response = json_create_object();
    json_object_set(response, "status", json_create_string("running"));
    json_object_set(response, "version", json_create_string("1.0.0"));
    json_object_set(response, "uptime", json_create_number(time(NULL)));
    
    response_json(ctx->res, response);
    json_destroy(response);
}

void create_user_handler(context_t *ctx) {
    if (!ctx->req->body) {
        response_set_status(ctx->res, HTTP_400_BAD_REQUEST);
        response_write(ctx->res, "Request body required", 21);
        return;
    }
    
    json_value_t *data = json_parse(ctx->req->body);
    if (!data) {
        response_set_status(ctx->res, HTTP_400_BAD_REQUEST);
        response_write(ctx->res, "Invalid JSON", 12);
        return;
    }
    
    json_value_t *name = json_object_get(data, "name");
    json_value_t *email = json_object_get(data, "email");
    
    if (!name || !email) {
        response_set_status(ctx->res, HTTP_400_BAD_REQUEST);
        response_write(ctx->res, "Name and email required", 23);
        json_destroy(data);
        return;
    }
    
    json_value_t *response = json_create_object();
    json_object_set(response, "message", json_create_string("User created successfully"));
    json_object_set(response, "user_id", json_create_number(rand() % 10000));
    json_object_set(response, "name", json_create_string(name->string_value));
    json_object_set(response, "email", json_create_string(email->string_value));
    
    response_set_status(ctx->res, HTTP_201_CREATED);
    response_json(ctx->res, response);
    
    json_destroy(data);
    json_destroy(response);
}

int logging_middleware(context_t *ctx) {
    printf("[%s] %s %s\n", 
           http_method_name(ctx->req->method),
           ctx->req->path,
           request_get_header(ctx->req, "User-Agent") ?: "Unknown");
    return 1;
}

int auth_middleware(context_t *ctx) {
    if (strncmp(ctx->req->path, "/api/", 5) == 0) {
        const char *auth = request_get_header(ctx->req, "Authorization");
        if (!auth || strncmp(auth, "Bearer token123", 15) != 0) {
            response_set_status(ctx->res, HTTP_401_UNAUTHORIZED);
            response_write(ctx->res, "Unauthorized", 12);
            return 0;
        }
    }
    return 1;
}

int main() {
    server_t *server = server_create(8080);
    if (!server) {
        fprintf(stderr, "Failed to create server\n");
        return 1;
    }
    
    server_enable_cors(server);
    server_static(server, "./static");
    
    server_use(server, "", logging_middleware);
    server_use(server, "/api", auth_middleware);
    
    server_get(server, "/", index_handler);
    server_get(server, "/users/:id", user_handler);
    server_get(server, "/api/status", api_status_handler);
    server_post(server, "/api/users", create_user_handler);
    
    printf("Starting server on http://localhost:8080\n");
    printf("Available endpoints:\n");
    printf("  GET  /                 - Homepage\n");
    printf("  GET  /users/:id        - Get user by ID\n");
    printf("  GET  /api/status       - API status (requires auth)\n");
    printf("  POST /api/users        - Create user (requires auth)\n");
    printf("\nFor API endpoints, use: Authorization: Bearer token123\n");
    
    int result = server_start(server);
    
    server_destroy(server);
    return result;
}