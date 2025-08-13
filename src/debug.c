#include "betanet_log.h"
#include <stdio.h>

// hex dump function - only compiled in debug builds
#if BETANET_LOG_LEVEL >= 3
void betanet_log_hex_dump(const char *prefix, const void *data, size_t size) {
    if (prefix != NULL) {
        printf("[DEBUG] %s:\n", prefix);
    }
    
    char ascii[17];
    size_t i;
    size_t j;
    ascii[16] = '\0';
    
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}
#endif