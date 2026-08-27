#include "aesarm.h"

#if defined(HAVE_ARM64)

#include <asm/hwcap.h>
#include <sys/auxv.h>

int aesarm_supported(void) {
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
}

#endif
