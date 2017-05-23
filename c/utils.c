#define _GNU_SOURCE   /* errno.h: program_invocation_short_name */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <regex.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"


static
int
map_level_priority(int level)
{
        switch (level) {
        case L_ERR:
                return LOG_ERR;
        case L_WARN:
                return LOG_WARNING;
        case L_INFO:
                return LOG_INFO;
        case L_DEBUG:
                return LOG_DEBUG;
        default:
                return LOG_NOTICE;
        }
}


struct rxc {
        // const char *pattern;
        regex_t rx;
        size_t pmatch_size;
        regmatch_t *pmatch;
        const char *string;
};


static int i_log_level = L_INFO;
static int i_use_syslog = 0;


void
log_level(int ll)
{
        i_log_level = ll;
}


void
use_syslog(int option, int facility)
{
        if (option == -1)
                option = LOG_PID;

        if (facility == -1)
                facility = LOG_DAEMON;

        openlog(program_invocation_short_name, option, facility);

        i_use_syslog = 1;
}


int
syslog_facility(const char *s)
{
#define SF(name, result) if (strcmp(s, name) == 0) return result;
        SF("kern",     LOG_KERN);
        SF("user",     LOG_USER);
        SF("mail",     LOG_MAIL);
        SF("daemon",   LOG_DAEMON);
        SF("auth",     LOG_AUTH);
        SF("syslog",   LOG_SYSLOG);
        SF("lpr",      LOG_LPR);
        SF("news",     LOG_NEWS);
        SF("uucp",     LOG_UUCP);
        SF("cron",     LOG_CRON);
        SF("authpriv", LOG_AUTHPRIV);
        SF("ftp",      LOG_FTP);
        SF("local0",   LOG_LOCAL0);
        SF("local1",   LOG_LOCAL1);
        SF("local2",   LOG_LOCAL2);
        SF("local3",   LOG_LOCAL3);
        SF("local4",   LOG_LOCAL4);
        SF("local5",   LOG_LOCAL5);
        SF("local6",   LOG_LOCAL6);
        SF("local7",   LOG_LOCAL7);
        return -1;
}


void
vlogmsg(int level, const char *format, va_list ap)
{
        if (level > i_log_level)
                return;

        if (i_use_syslog) {
                vsyslog(map_level_priority(level), format, ap);
        } else {
                vfprintf(stderr, format, ap);
                fprintf(stderr, "\n");
        }
}



void
logmsg(int level, const char *format, ...)
{
        if (level > i_log_level)
                return;

        va_list ap;
        va_start(ap, format);
        vlogmsg(level, format, ap);
        va_end(ap);
}


void
errexit(const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vlogmsg(L_ERR, format, ap);
        exit(EXIT_FAILURE);
}


void
syserr(const char *format, ...)
{
        char errbuf[1024];
        char *errstr = strerror_r(errno, errbuf, sizeof(errbuf)); // _GNU_SOURCE variant
        va_list ap;
        va_start(ap, format);
        char msgbuf[2048];
        vsnprintf(msgbuf, sizeof(msgbuf), format, ap);
        errexit("%s: %s(%d)", msgbuf, errstr, errno);
}


void
print_hex_dump(FILE *f, const void *bufptr, int length)
{
        const uint8_t *buf = bufptr;

        if (length < 1)
                return;

        int lines = (length - 1) / 16 + 1;

        for (int l = 0; l < lines; l++) {
                for (int k = 0; k < 16; k++) {
                        if (k == 8)
                                fprintf(f, " ");
                        int i = l * 16 + k;
                        if (i < length)
                                fprintf(f, "%02x ", buf[i]);
                        else
                                fprintf(f, "   ");
                }

                fprintf(f, "\t");

                for (int k = 0; k < 16; k++) {
                        int i = l * 16 + k;
                        if (i == length)
                                break;
                        if (0x20 <= buf[i] && buf[i] <= 0x7e)
                                fprintf(f, "%c", buf[i]);
                        else
                                fprintf(f, ".");
                }

                fprintf(f, "\n");
        }
}


void
putsn(const uint8_t *s, size_t ln)
{
        for (size_t i = 0; i < ln && s[i]; i++)
                putchar(s[i]);
        printf("\n");
}


char *
strtoup(char *str)
{
        for (; *str; str++) {
                char u = toupper(*str);
                if (u != *str)
                        *str = u;
        }
        return str;
}


struct rxc *
rxc_make(const char *pattern)
{
        struct rxc *rxc = calloc(1, sizeof(struct rxc));
        // rxc->pattern = strdup(pattern);

        int rc = regcomp(&rxc->rx, pattern, REG_EXTENDED|REG_ICASE);
        if (rc) {
                char errbuf[1024];
                regerror(rc, &rxc->rx, errbuf, sizeof(errbuf));
                errexit("regcomp(%s): %s", pattern, errbuf);
        }

        rxc->pmatch_size = rxc->rx.re_nsub + 1;
        rxc->pmatch = malloc(rxc->pmatch_size * sizeof(regmatch_t));

        return rxc;
}


int
rxc_match(struct rxc *rxc, const char *string)
{
        rxc->string = string;
        return regexec(&rxc->rx, string, rxc->pmatch_size, rxc->pmatch, 0);
}


char *
rxc_capture(struct rxc *rxc, int n, char *buf, size_t bufsize)
{
        regmatch_t *m = rxc->pmatch + n;
        size_t ln = m->rm_eo - m->rm_so;
        if (bufsize < ln+1)
                return NULL;
        memcpy(buf, rxc->string + m->rm_so, ln);
        buf[ln] = 0;
        return buf;
}


size_t
fread_all(FILE* f, void **ptr)
{
        char buf[20480];
        char *result_buffer = NULL;
        size_t l, size = 0;

        while ((l = fread(buf, 1, sizeof(buf), f)) > 0) {
                size_t newsize = size + l;
                result_buffer = realloc(result_buffer, newsize);
                memcpy(result_buffer+size, buf, l);
                size = newsize;
        }

        *ptr = result_buffer;

        return size;
}


size_t
read_all(const char *filename, void **ptr)
{
        FILE *f = fopen(filename, "r");
        if (f == NULL)
                return 0;
        *ptr = NULL;
        size_t len = fread_all(f, ptr);
        fclose(f);
        return len;
}


char *
ip_to_s(uint32_t ip, char *s)
{
        uint8_t *p = (uint8_t*)(&ip);
        sprintf(s, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
        return s;
}


int
string_to_integer(const char *s, int min, int max, int *result)
{
        char *endptr;

        long val = strtoul(s, &endptr, 10);

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0))
                return -1;

        if (endptr == s)
                return -2;

        if (max >= min && (val < min || val > max)) {
                log_debug("%ld < %d || %ld > %d (%d >= %d)\n", val, min, val, max, max, min);
                return -3;
        }

        *result = val;

        return 0;
}


int
str_to_ulong(const char *s, char **endptr, unsigned long *n, unsigned long max)
{
        char *ptr;

        if (endptr == NULL)
                endptr = &ptr;

        *n = strtoul(s, endptr, 10);

        if (errno == ERANGE && *n == ULONG_MAX)
                goto err;

        if (*endptr == s)
                goto err;

        if (*n > max)
                goto err;

        return 0;

 err:
        return -1;
}


int
parse_sockaddr(const char *s, struct sockaddr_in *sin)
{
        const char *p = strchr(s, ':');
        if (p == NULL)
                goto badaddr;

        size_t ln = p - s;
        char *ip = alloca(ln + 1);
        memcpy(ip, s, ln);
        ip[ln] = 0;

        struct in_addr in_addr;
        if (inet_pton(AF_INET, ip, &in_addr) != 1)
                goto badaddr;

        sin->sin_addr = in_addr;

        int port;
        if (string_to_integer(s + ln + 1, 0, 65535, &port) < 0)
                goto badaddr;
        sin->sin_port = htons(port);

        sin->sin_family = AF_INET;

        return 0;

 badaddr:
        fprintf(stderr, "Invalid sockaddr '%s'\n", s);
        return -1;
}


int
parse_ipnet(const char *s, struct ipnet *ipnet)
{
        int m = 32;

        const char *ip = s;
        char *as = NULL;

        char *p = strchr(s, '/');

        if (p != NULL) {
                if ((p - s) < 7 || (p - s) > 15)
                        goto err;

                char *ms = p + 1;

                if (!isdigit(*ms))
                        goto err;

                if (ms[1] &&
                    (!isdigit(ms[1]) || ms[2]))
                        goto err;

                m = atoi(ms);
                if (m < 0 || m > 32)
                        goto err;

                as = alloca(p - s + 1);
                memcpy(as, s, p - s);
                as[p-s] = 0;

                ip = as;
        }

        struct in_addr addr;

        if (0 == inet_aton(ip, &addr))
                goto err;

        ipnet->masklen = m;
        ipnet->mask = m == 0 ? 0 : (~0) << (32 - m);
        ipnet->ip = ntohl(addr.s_addr) & ipnet->mask;

        return 0;

 err:
        return -1;
}


static void goto_background(void);
static void redirect_std(void);
static int lockpidfile(const char *filename);


void
daemonize(const char *pidfile, int facility)
{
        goto_background();
        lockpidfile(pidfile);
        log_info("daemonized");
        redirect_std();
        use_syslog(0, facility);
}


void
goto_background(void)
{
        if(1 == getppid())
                return;

        pid_t pid = fork();
        if(-1 == pid)
                syserr("fork()");

        if(pid > 0)
                exit(EXIT_SUCCESS);

        umask(027);

        if(-1 == setsid())
                syserr("setsid()");

        if((chdir("/")) < 0)
                syserr("chdir()");
}


/* Redirect standard files to /dev/null */
void
redirect_std(void)
{
        if (NULL == freopen("/dev/null", "r", stdin))
                errexit("freopen failed");
        if (NULL == freopen("/dev/null", "r", stdout))
                errexit("freopen failed");
        if (NULL == freopen("/dev/null", "r", stderr))
                errexit("freopen failed");
}


static
int
lockpidfile(const char *filename)
{
        int fd = open(filename, O_CREAT|O_WRONLY, 0640);
        if (fd == -1)
                syserr("open(%s)", filename);

        if (-1 == flock(fd, LOCK_EX|LOCK_NB))
                syserr("flock(%s), LOCK_EX", filename);

        char buf[20];
        snprintf(buf, sizeof(buf), "%d", getpid());

        ssize_t ln = strlen(buf);

        if (write(fd, buf, ln) != ln)
                syserr("write()");

        if (-1 == fsync(fd))
                syserr("fsync(%s)", filename);

        return fd;
}


void
default_pidfile(char *buffer, size_t buflen, const char *piddir)
{
        CSNPRINTF(buffer, buflen, "%s/%s.pid", piddir, program_invocation_short_name);
}


uint64_t
gettime(void)
{
        struct timeval tv;
        // int gettimeofday(struct timeval *tv, struct timezone *tz);
        if (-1 == gettimeofday(&tv, NULL))
                syserr("gettimeofday()");
        return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}


void
set_sig_handler(int signum, void (*handler)(int), int flags)
{
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = flags;

        if (-1 == sigaction(signum, &sa, NULL))
                syserr("sigaction()");
}


int
file_exists(const char *path)
{
        struct stat st;
        int rc = stat(path, &st);

        if (rc == 0)
                return 1;

        if (rc == -1 && errno == ENOENT)
                return 0;

        errexit("stat(%s)", path);
}
