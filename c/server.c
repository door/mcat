#define _GNU_SOURCE         // asprintf

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include <microhttpd.h>
#include <openssl/sha.h>

#include "utils.h"


#define BLOCKSIZE 1000


struct FileReader {
        size_t blocksize;
        size_t filesize;
        size_t blocks;
        const char *basename;
        FILE *file;
};

struct FileReader* FileReader_new(const char *filename, size_t blocksize);


struct UdpPusher {
        struct sockaddr_in addr;
        int socket;
        struct timeval interval;
        struct FileReader *reader;
};

struct UdpPusher* UdpPusher_new(struct sockaddr_in addr, size_t speed, struct FileReader *reader);
void UdpPusher_run(struct UdpPusher *self);


int http_server (void *cls, struct MHD_Connection *connection,
                 const char *url,
                 const char *method, const char *version,
                 const char *upload_data,
                 size_t *upload_data_size, void **con_cls);


void calc_hash(const char *filename);

size_t parse_rate(const char *s);
int parse_url(const char *s, char **path, uint16_t *http_port);

struct WebApp {
        struct FileReader *reader;
        const char *path;
};


char *FileHashSum = NULL;



int main(int argc, char **argv)
{
        struct sockaddr_in udp_addr;
        char *filename = NULL;
        size_t bitrate = 0;
        size_t blocksize = 0;
        uint16_t http_port;
        char *control_url = NULL;

        for (;;) {
                int option_index = 0;
                static struct option long_options[] = {
                        {"address", required_argument, 0, 'a'},
                        {"control-url", required_argument, 0, 'c'},
                        {"file", required_argument, 0, 'f'},
                        {"bitrate", required_argument, 0, 'r'},
                        {"payload-size", required_argument, 0, 's'},
                        {"help", no_argument, 0, 'h'},
                        {0,0,0,0}
                };
                int c = getopt_long(argc, argv, "a:c:f:r:s:h",
                                    long_options, &option_index);

                if (c == -1)
                        break;

                switch(c) {
                case 'a':
                        {
                                char *p = optarg;
                                if (strncmp(p, "udp://", 6) == 0)
                                        p += 6;

                                if (parse_sockaddr(p, &udp_addr) == -1)
                                        errexit("Invalid address: %s", optarg);
                        }
                        break;

                case 'c':
                        if (parse_url(optarg, &control_url, &http_port) == -1)
                                errexit("Invalid URL %s", optarg);
                        break;

                case 'f':
                        filename = strdup(optarg);
                        break;

                case 'r':
                        bitrate = parse_rate(optarg);
                        if (bitrate == 0)
                                errexit("Invalid bitrate: %s", optarg);
                        break;

                case 's':
                        {
                                int v;
                                if (string_to_integer(optarg, 1, 1500, &v) < 0)
                                        errexit("Invalid payload size: %s", optarg);
                                blocksize = v;
                        }
                        break;

                case 'h':
                        printf("Usage: %s -a ADDRESS -c URL -f FILE -r SPEED [-s SIZE]", argv[0]);
                        exit(0);
                        break;
                }

        };

        // printf("address: %s:%d", inet_ntoa(udp_addr.sin_addr), ntohs(udp_addr.sin_port));

        if (!(udp_addr.sin_family && control_url && filename && bitrate))
                errexit("Not all reqiured parametes set, run with '-h' key");

        if (!blocksize)
                blocksize = BLOCKSIZE;

        pthread_t calc_hash_tid;
        void *calc_hash_fn(void *data) {
                (void)data;
                calc_hash(filename);
                return NULL;
        };
        int rc = pthread_create(&calc_hash_tid, NULL, calc_hash_fn, NULL);
        if (rc != 0) {
                errno = rc;
                syserr("pthread_create()");
        }

        void *pusher_fn(void *data) {
                (void)data;
                struct FileReader *reader = FileReader_new(filename, blocksize);
                struct UdpPusher *pusher = UdpPusher_new(udp_addr, bitrate, reader);
                UdpPusher_run(pusher);
                return NULL;
        };

        pthread_t pusher_tid;
        rc = pthread_create(&pusher_tid, NULL, pusher_fn, NULL);
        if (rc != 0) {
                errno = rc;
                syserr("pthread_create()");
        }

        struct WebApp webapp;
        webapp.reader = FileReader_new(filename, blocksize);
        webapp.path = control_url;

        struct MHD_Daemon *httpd =
                MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, http_port, NULL, NULL,
                &http_server, &webapp, MHD_OPTION_END);

        if (httpd == NULL)
                errexit("Cannot launch httpd");

        pthread_join(pusher_tid, NULL);
}


struct FileReader*
FileReader_new(const char *filename, size_t blocksize)
{
        struct FileReader *self = malloc(sizeof(struct FileReader));

        const char *p = strrchr(filename, '/');
        self->basename = strdup(p ? p+1 : filename);

        struct stat sb;
        if (stat(filename, &sb) != 0)
                syserr("stat()");

        self->filesize = sb.st_size;

        self->file = fopen(filename, "rb");
        if (self->file == NULL)
                syserr("fopen()");

        self->blocksize = blocksize;

        self->blocks = self->filesize / blocksize +
                (self->filesize % blocksize ? 1 : 0);

        return self;
}


int
FileReader_seek_block(struct FileReader *self, size_t blockno)
{
        if (blockno >= self->blocks)
                return -1;

        if (fseek(self->file, self->blocksize * blockno, SEEK_SET) == -1)
                syserr("fseek()");

        return 0;
}


size_t
FileReader_read_block(struct FileReader *self, void *buffer)
{
        size_t size = fread(buffer, 1, self->blocksize, self->file);
        if (size != self->blocksize) {
                if (ferror(self->file))
                        errexit("fread()");
        }
        if (size == 0) {
                if (feof(self->file))
                        rewind(self->file);
                else
                        errexit("fread()");
        }
        return size;
}


struct UdpPusher*
UdpPusher_new(struct sockaddr_in addr, size_t speed, struct FileReader *reader)
{
        struct UdpPusher *self = malloc(sizeof(struct UdpPusher));

        self->addr = addr;

        if ((self->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                syserr("socket()");

        size_t pktsize = 4 + reader->blocksize; // Packet number + payload
        uint64_t interval = (1000000*pktsize) / (speed/8); // интервал в микросекундах между пакетами
        // printf("interval=%ld\n", interval);
        self->interval.tv_sec  = interval / 1000000;
        self->interval.tv_usec = interval % 1000000;

        // printf("sec: %ld\n", self->interval.tv_sec);
        // printf("usec: %ld\n", self->interval.tv_usec);

        self->reader = reader;
        return self;
}


void
UdpPusher_run(struct UdpPusher *self)
{
        uint8_t *buffer = malloc(self->reader->blocksize + 4);

        for (;;) {
                for (int blockno = 0;; blockno++) {

                        struct timeval t1, t2, td;

                        if (gettimeofday(&t1, NULL) == -1)
                                syserr("gettimeofday()");

                        size_t size = FileReader_read_block(self->reader, buffer+4);
                        if (size == 0)
                                break;

                        *((uint32_t*)buffer) = htonl(blockno);

                        ssize_t ss = sendto(self->socket, buffer, size + 4, 0, (const struct sockaddr *)&self->addr, sizeof(self->addr));
                        if (ss == -1)
                                syserr("sendto()");
                        // printf("block sent %d\n", blockno);

                        if (gettimeofday(&t2, NULL) == -1)
                                syserr("gettimeofday()");

                        timersub(&t2, &t1, &td);

                        if (timercmp(&td, &self->interval, <)) {
                                struct timeval tsv;
                                timersub(&self->interval, &td, &tsv);
                                struct timespec ts;
                                ts.tv_sec = tsv.tv_sec;
                                ts.tv_nsec = tsv.tv_usec * 1000;
                                // printf("%ld, %ld\n", ts.tv_sec, ts.tv_nsec);
                                nanosleep(&ts, NULL);
                        }
                }
        }
}


size_t
parse_rate(const char *s)
{
        size_t len = strlen(s);
        if (len < 1)
                return 0;
        size_t m = 1;
        switch (s[len-1]) {
        case 'k':
                m = 1024;
                break;
        case 'm':
                m = 1024 * 1024;
                break;
        default:
                break;
        }

        int r;
        if (string_to_integer(s, 1, 1000000000L, &r) < 0)
                return 0;

        return (size_t)r*m;
}


int
http_server(void *cls, struct MHD_Connection *connection,
            const char *url,
            const char *method, const char *version,
            const char *upload_data,
            size_t *upload_data_size, void **con_cls)
{

        (void)upload_data;
        (void)upload_data_size;
        (void)con_cls;

        if (strcmp(method, "GET") != 0)
                goto err404;

        struct WebApp* webapp = cls;
        const char *prefix = webapp->path;

        printf("prefix: %s, method: %s, version: %s, url: %s\n", prefix, method, version, url);

        size_t prefix_len = strlen(prefix);

        if (strlen(url) < prefix_len+2)
                goto err404;

        if (strncmp(url, prefix, prefix_len) != 0)
                goto err404;

        url += prefix_len;

        int answer(int code, void *reply, size_t reply_length,
                   int mem_type, const char *content_type) {
                struct MHD_Response *response =
                        MHD_create_response_from_buffer(reply_length, reply, mem_type);
                int ret = MHD_add_response_header(response, "Content-Type", content_type);
                ret = MHD_queue_response(connection, code, response);
                MHD_destroy_response(response);
                return ret;
        }

        struct FileReader* reader = webapp->reader;

        if (strcmp(url, "/info") == 0) {
                char *reply;
                asprintf(&reply, "%ld %ld %s",
                         reader->blocksize, reader->filesize, reader->basename);

                return answer(200, reply, strlen(reply), MHD_RESPMEM_MUST_FREE, "text/plain");
        }

        if (strcmp(url, "/hash") == 0) {
                if (FileHashSum) {
                        return answer(200, FileHashSum, strlen(FileHashSum), MHD_RESPMEM_PERSISTENT, "text/plain");
                } else {
                        static char *reply = "Not yet available";
                        return answer(424, reply, strlen(reply), MHD_RESPMEM_PERSISTENT, "text/plain");
                }
        }


        const char *bp =  "/block/";
        size_t bpl = strlen(bp);

        size_t blockno;

        if (strlen(url) > bpl &&
            strncmp(url, bp, bpl) == 0 &&
            str_to_ulong(url + bpl, NULL, &blockno, 10000000) == 0) {

                if (FileReader_seek_block(reader, blockno) == -1)
                        goto err404;

                uint8_t *buffer = malloc(reader->blocksize);
                size_t size = FileReader_read_block(reader, buffer);
                if (size == 0) {
                        // should not happen
                        free(buffer);
                        goto err404;
                }
                return answer(200, buffer, size, MHD_RESPMEM_MUST_FREE, "application/binary");
        }

 err404:
        {
                static char *reply = "Not found";
                return answer(200, reply, strlen(reply), MHD_RESPMEM_PERSISTENT, "text/plain");
        }
}


void
calc_hash(const char *filename)
{
        size_t bufsize = 100000;
        struct FileReader *reader = FileReader_new(filename, bufsize);
        uint8_t *buffer = malloc(bufsize);

        SHA_CTX ctx;
        SHA1_Init(&ctx);

        for (;;) {
                size_t size = FileReader_read_block(reader, buffer);
                if (size <= 0)
                        break;
                SHA1_Update(&ctx, buffer, size);
        }

        // printf("hash ready\n");

        uint8_t hash[SHA_DIGEST_LENGTH];
        SHA1_Final(hash, &ctx);

        char *hash_str = malloc(SHA_DIGEST_LENGTH*2+1);

        for(size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
                static char chars[] = "0123456789abcdef";
                hash_str[i*2] = chars[(hash[i] >> 4) & 0x0f];
                hash_str[i*2+1] = chars[hash[i] & 0x0f];
        }

        hash_str[SHA_DIGEST_LENGTH*2] = 0;

        FileHashSum = hash_str;
}


int
parse_url(const char *s, char **path, uint16_t *http_port)
{
        regex_t rx;

        if (regcomp(&rx, "^(https?)://([^:/]+)(:([0-9]+))?(/.*)?$", REG_EXTENDED))
                errexit("regcomp()");

        size_t pmatch_size = rx.re_nsub + 1;
        regmatch_t *pmatch = alloca(pmatch_size * sizeof(regmatch_t));
        if (regexec(&rx, s, pmatch_size, pmatch, 0))
                return -1;

#define capture(i) ({                                           \
                        regmatch_t *m = pmatch + i;             \
                        size_t ln = m->rm_eo - m->rm_so;        \
                        char *p = alloca(ln+1);                 \
                        memcpy(p, s + m->rm_so, ln);            \
                        p[ln] = 0;                              \
                        p;                                      \
                })

        char *proto = capture(1);
        char *port = capture(4);
        *path = capture(5);

        if (strcmp(proto, "https") == 0)
                errexit("https not supported");

        if (strcmp(proto, "http") != 0)
                errexit("Unkwnown protocol: %s", proto);

        int result;
        if (string_to_integer(port, 1, 65535, &result) < 0)
                errexit("Invalid port number: %s", port);

        *http_port = result;

        char *path1 = capture(5);
        if (strlen(path1) == 0)
                *path = strdup("/");
        else
                *path = strdup(path1);

        return 0;
}

