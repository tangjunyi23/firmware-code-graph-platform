typedef int (*route_handler_t)(const char *request);

struct route_entry {
    const char *path;
    route_handler_t handler;
};

int status_handler(const char *request) {
    return request != 0;
}

int reboot_handler(const char *request) {
    return request == 0;
}

struct route_entry routes[] = {
    {"/api/status", status_handler},
    {"/goform/reboot", reboot_handler},
};

int main(int argc, char **argv) {
    struct route_entry *route = &routes[argc & 1];
    return route->handler(argv[0]);
}
