/* SPDX-License-Identifier: AGPL-3.0-only */
/* Wutong Core C ABI (v0). All strings are UTF-8, NUL-terminated.
 * Every char* returned by this library MUST be released with wutong_string_free.
 * Functions never unwind across the boundary (panics are caught and reported). */
#ifndef WUTONG_H
#define WUTONG_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* ABI version; bump on breaking changes. */
uint32_t wutong_abi_version(void);
/* Static implementation string, do NOT free. */
const char *wutong_implementation(void);
/* Canonicalize JSON (strict parse + JCS). Returns 0 on success; *out (canonical) or *err (message). */
int32_t wutong_jcs(const uint8_t *json, size_t len, char **out, char **err);
/* Strictly parse + schema + semantic validate an envelope. Returns 0 on success, else *err = "ERR_*: detail". */
int32_t wutong_validate_envelope(const uint8_t *json, size_t len, char **err);
/* sha256:<hex> of raw bytes. */
char *wutong_sha256(const uint8_t *data, size_t len);
void wutong_string_free(char *s);

#ifdef __cplusplus
}
#endif
#endif
