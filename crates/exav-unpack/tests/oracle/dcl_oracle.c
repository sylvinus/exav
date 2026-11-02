/* Differential oracle for formats/dcl_explode.rs: blast.c from zlib's
 * contrib/blast (Mark Adler, zlib licence), which decodes the PKWARE Data
 * Compression Library format.
 *
 * Build and run: see build.sh. Input on stdin, a sequence of records:
 *   u32 cap, u32 src_len, src bytes             (little endian)
 * Output on stdout, one record per input record:
 *   u8 status, u32 out_len, out bytes
 * status: 0 ok, 1 output past the cap, 2 source truncated, 3 invalid.
 * At most cap bytes of output are reported.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blast.h"

struct in_state {
  unsigned char *p;
  unsigned n;
};

static unsigned feed(void *how, unsigned char **buf) {
  struct in_state *s = how;
  unsigned n = s->n;
  *buf = s->p;
  s->p += n;
  s->n = 0;
  return n;
}

struct out_state {
  unsigned char *p;
  size_t cap, len;
};

static int sink(void *how, unsigned char *buf, unsigned len) {
  struct out_state *o = how;
  size_t room = o->cap - o->len;
  size_t take = len < room ? len : room;
  memcpy(o->p + o->len, buf, take);
  o->len += take;
  return take < len;
}

static int read_exact(void *p, size_t n) { return fread(p, 1, n, stdin) == n; }

int main(void) {
  uint32_t head[2];
  while (read_exact(head, sizeof head)) {
    size_t cap = head[0], src_len = head[1];
    unsigned char *src = malloc(src_len ? src_len : 1);
    unsigned char *dst = malloc(cap ? cap : 1);
    if (!read_exact(src, src_len)) return 2;
    struct in_state in = {src, (unsigned)src_len};
    struct out_state out = {dst, cap, 0};
    int r = blast(feed, &in, sink, &out, NULL, NULL);
    uint8_t code = r == 0 ? 0 : r == 1 ? 1 : r == 2 ? 2 : 3;
    uint32_t n = (uint32_t)out.len;
    fwrite(&code, 1, 1, stdout);
    fwrite(&n, 4, 1, stdout);
    fwrite(dst, 1, n, stdout);
    free(src);
    free(dst);
  }
  fflush(stdout);
  return 0;
}
