#ifndef BETANET_LOG_H
#define BETANET_LOG_H

#include <stdio.h>
#include <stddef.h>

// log levels
typedef enum {
    BETANET_LOG_ERROR = 0,
    BETANET_LOG_WARN = 1,
    BETANET_LOG_INFO = 2,
    BETANET_LOG_DEBUG = 3
} betanet_log_level_t;

// compile-time log level control
// set BETANET_LOG_LEVEL to desired maximum level
// debug builds: -DBETANET_LOG_LEVEL=3
// release builds: -DBETANET_LOG_LEVEL=0 or undefined for no logging
#ifndef BETANET_LOG_LEVEL
#ifdef NDEBUG
#define BETANET_LOG_LEVEL -1  // no logging in release builds
#else
#define BETANET_LOG_LEVEL 3   // all logging in debug builds
#endif
#endif

// log macros that compile out when level is disabled
#if BETANET_LOG_LEVEL >= 0
#define BETANET_LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#else
#define BETANET_LOG_ERROR(fmt, ...)
#endif

#if BETANET_LOG_LEVEL >= 1
#define BETANET_LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)
#else
#define BETANET_LOG_WARN(fmt, ...)
#endif

#if BETANET_LOG_LEVEL >= 2
#define BETANET_LOG_INFO(fmt, ...) \
    printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#else
#define BETANET_LOG_INFO(fmt, ...)
#endif

#if BETANET_LOG_LEVEL >= 3
#define BETANET_LOG_DEBUG(fmt, ...) \
    printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define BETANET_LOG_DEBUG(fmt, ...)
#endif

// hex dump function - only available in debug builds
#if BETANET_LOG_LEVEL >= 3
void betanet_log_hex_dump(const char *prefix, const void *data, size_t size);
#define BETANET_LOG_HEX(prefix, data, size) betanet_log_hex_dump(prefix, data, size)
#else
#define BETANET_LOG_HEX(prefix, data, size)
#endif

#endif // BETANET_LOG_H
