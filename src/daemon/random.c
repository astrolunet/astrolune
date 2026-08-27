/* Platform entropy for key generation. See random.h. */

#include "random.h"

#if defined(AL_OS_WINDOWS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <stdio.h>
#endif

al_bool os_random_bytes(void *buffer, al_size length) {
    if (buffer == NULL || length == 0u) return AL_FALSE;

#if defined(AL_OS_WINDOWS)
    NTSTATUS status = BCryptGenRandom(
        NULL, (PUCHAR)buffer, (ULONG)length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) ? AL_TRUE : AL_FALSE;
#else
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) return AL_FALSE;
    al_size read = fread(buffer, 1u, length, urandom);
    (void)fclose(urandom);
    return read == length ? AL_TRUE : AL_FALSE;
#endif
}
