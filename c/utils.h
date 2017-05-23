#include <ctype.h> // tolower
#include <stdint.h> // uintX_t
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum {
        L_ERR,
        L_WARN,
        L_INFO,
        L_DEBUG
};


void log_level(int);
void use_syslog(int option, int facility);
int syslog_facility(const char *s);

void logmsg(int level, const char *format, ...) 
        __attribute__ ((format (printf, 2, 3)));

#define log_err(format, ...) logmsg(L_ERR, format, ## __VA_ARGS__)
#define log_warn(format, ...) logmsg(L_WARN, format, ## __VA_ARGS__)
#define log_info(format, ...) logmsg(L_INFO, format, ## __VA_ARGS__)
#define log_debug(format, ...) logmsg(L_DEBUG, format, ## __VA_ARGS__)

void errexit(const char *format, ...)
        __attribute__ ((format (printf, 1, 2), noreturn));

void syserr(const char *format, ...);

// void daemonize(void);
void daemonize(const char *pidfile, int facility);
// int lockpidfile(const char *filename);
void default_pidfile(char *buffer, size_t buflen, const char *piddir);

void set_sig_handler(int signum, void (*handler)(int), int flags);

void print_hex_dump(FILE *f, const void *bufptr, int length);

size_t read_all(const char *filename, void **ptr);
size_t fread_all(FILE* f, void **ptr);
int file_exists(const char *path);

uint64_t gettime(void);

#define min(a, b) ({                            \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a < _b ? _a : _b;      \
                })

#define max(a, b) ({                            \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a > _b ? _a : _b;      \
                })


#define array_size(a) (sizeof(a)/sizeof(*a))


struct rxc;

struct rxc *rxc_make(const char *pattern);
int rxc_match(struct rxc *rxc, const char *string);
char *rxc_capture(struct rxc *rxc, int n, char *buf, size_t bufsize);




void putsn(const uint8_t *s, size_t ln);

#define zs(p, l) ({                                     \
                        char *_zs_ptr_ = alloca(l+1);   \
                        memcpy(_zs_ptr_, p, l);         \
                        _zs_ptr_[l] = 0;                \
                        _zs_ptr_;                       \
                })


char * ip_to_s(uint32_t ip, char *s);
#define ip_to_sa(ip) ip_to_s(ip, alloca(16))


int string_to_integer(const char *s, int min, int max, int *result);
int str_to_ulong(const char *s, char **endptr, unsigned long *n, unsigned long max);

#define CSNPRINTF(buffer, size, format, ...)                            \
        do {                                                            \
                if (snprintf(buffer, size, format, ## __VA_ARGS__) >= (int)size) \
                        errexit("Value too long"); }                    \
        while (0)


struct sockaddr_in;

int parse_sockaddr(const char *s, struct sockaddr_in *sin);


static
inline
void
memcpy_tolower(char *dst, const char *src, size_t len)
{
        for (size_t i = 0; i < len; i++)
                dst[i] = tolower(src[i]);
}


struct ipnet {
        uint32_t ip;
        uint32_t mask;
        uint8_t masklen;
};


int parse_ipnet(const char *s, struct ipnet *ipnet);


#if WITH_LENVAL
//
// lenval
//
struct lenval {
        size_t len;
        const void *val;
};

typedef struct lenval lenval_t;


#define lvzs(lv)  ({(lv.val && lv.len) ? zs(lv.val, lv.len) : "";})
#define lvpzs(lvp)  ({(lvp->val && lvp->len) ? zs(lvp->val, lvp->len) : "";})


static
inline
int 
lenval_compare(const lenval_t *lv1, const lenval_t *lv2)
{
        int equal = lv1->len == lv2->len && !memcmp(lv1->val, lv2->val, lv1->len);
        return !equal;
}


static
inline
lenval_t *
lenval_dup(lenval_t *lv)
{
        lenval_t *lvnew = malloc(sizeof(lenval_t));
        lvnew->len = lv->len;
        void *p = malloc(lv->len);
        memcpy(p, lv->val, lv->len);
        lvnew->val = p;
        return lvnew;
}


static
inline
void
lenval_free(lenval_t *lv)
{
        free((void*)lv->val);
        free(lv);
}


/* static */
/* inline */
/* void */
/* lenval_tolower(lenval_t *lv) */
/* { */
/*         memcpy_tolower((char*)lv->val, lv->val, lv->len); */
/* } */


#endif /* WITH_LENVAL */


#ifdef ZMQ_VERSION

static
void *
simple_zmq_connect(int type, const char *addr, void **context)
{
        void *zmq_context;
        if (NULL == (zmq_context = zmq_ctx_new()))
                syserr("zmq_ctx_new()");

        void *zmq_sock;
        if (NULL == (zmq_sock = zmq_socket(zmq_context, type)))
                syserr("zmq_socket()");

        switch (type) {
        case ZMQ_PUSH:
                if (-1 == zmq_connect(zmq_sock, addr))
                        syserr("zmq_connect(\"%s\")", addr);
                break;

        case ZMQ_PULL:
                if (-1 == zmq_bind(zmq_sock, addr))
                        syserr("zmq_bind(\"%s\")", addr);
                break;

        default:
                errexit("simple_zmq_connect(): unknown type");
        }

        if (context)
                *context = zmq_context;

        return zmq_sock;
}

#endif /* ZMQ_VERSION_MAJOR */


