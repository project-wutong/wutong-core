/* SPDX-License-Identifier: AGPL-3.0-only */
#include "wutong.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    const char *in = "{\"b\":1,\"a\":\"x\"}";
    char *out = NULL, *err = NULL;
    if (wutong_jcs((const uint8_t *)in, strlen(in), &out, &err) != 0) { fprintf(stderr, "%s\n", err); return 1; }
    if (strcmp(out, "{\"a\":\"x\",\"b\":1}") != 0) return 2;
    wutong_string_free(out);
    char *d = wutong_sha256((const uint8_t *)"", 0);
    if (strcmp(d, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) return 3;
    wutong_string_free(d);
    printf("ok %s abi=%u\n", wutong_implementation(), wutong_abi_version());
    return 0;
}
