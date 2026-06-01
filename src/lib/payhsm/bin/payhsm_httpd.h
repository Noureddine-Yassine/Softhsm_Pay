#ifndef PAYHSM_HTTPD_H
#define PAYHSM_HTTPD_H

/*
 * Run the HTTP admin server (blocking).
 * port        : TCP port to listen on (default 8765)
 * static_root : directory for static files, or NULL to use compiled default
 */
void payhsm_httpd_serve(int port, const char *static_root);

#endif /* PAYHSM_HTTPD_H */
