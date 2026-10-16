/* Differential oracle for formats/lzfse.rs: Apple's reference LZFSE decoder
 * (BSD-3-Clause, github.com/lzfse/lzfse), driven through its internal state
 * API so that the bytes written before a failure are reported too.
 *
 * Build and run: see build.sh. Optional argument: the destination fill byte.
 * Input on stdin, a sequence of records:
 *   u32 dst_size, u32 src_len, src bytes        (little endian)
 * Output on stdout, one record per input record:
 *   u8 status, u32 out_len, out bytes
 * status: 0 ok, 1 destination full, 2 source truncated, 3 error.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzfse_internal.h"

static int read_exact(void *p, size_t n) { return fread(p, 1, n, stdin) == n; }

int main(int argc, char **argv) {
  /* The byte the destination is filled with first. The reference does not
   * clear it, and a stream may make it copy from bytes it never wrote: two runs
   * with different fills tell such a stream by its different output. */
  int fill = argc > 1 ? atoi(argv[1]) : 0;
  lzfse_decoder_state *s = malloc(sizeof(*s));
  uint32_t head[2];
  while (read_exact(head, sizeof head)) {
    size_t dst_size = head[0], src_len = head[1];
    /* Exact-size heap blocks, so a read or write past either is an ASan error. */
    uint8_t *src = malloc(src_len ? src_len : 1);
    uint8_t *dst = malloc(dst_size ? dst_size : 1);
    if (!read_exact(src, src_len)) return 2;
    memset(dst, fill, dst_size);
    memset(s, 0, sizeof(*s));
    s->src = s->src_begin = src;
    s->src_end = src + src_len;
    s->dst = s->dst_begin = dst;
    s->dst_end = dst + dst_size;
    int st = lzfse_decode(s);
    uint8_t code = st == LZFSE_STATUS_OK         ? 0
                   : st == LZFSE_STATUS_DST_FULL ? 1
                   : st == LZFSE_STATUS_SRC_EMPTY ? 2
                                                  : 3;
    uint32_t n = (uint32_t)(s->dst - dst);
    fwrite(&code, 1, 1, stdout);
    fwrite(&n, 4, 1, stdout);
    fwrite(dst, 1, n, stdout);
    free(src);
    free(dst);
  }
  fflush(stdout);
  free(s);
  return 0;
}
