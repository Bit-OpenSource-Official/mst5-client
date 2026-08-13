#include "mst5.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    if (mst5_abi_version() != MST5_ABI_VERSION) return 1;
    if (strcmp(mst5_version(), "0.4.0") != 0) return 2;
    mst5_buffer_free((mst5_buffer){0});
    puts("mst5-client C ABI smoke: OK");
    return 0;
}
