#ifndef ASTROLUNE_FUZZ_INPUT_H
#define ASTROLUNE_FUZZ_INPUT_H

#include "astrolune/base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fuzz_hex_digit(al_u8 value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static const al_u8 *fuzz_normalize(const al_u8 *data, al_size size,
                                   al_size *normalized_size,
                                   al_u8 **allocation) {
    *normalized_size = size;
    *allocation = NULL;
    if (size < 4u || memcmp(data, "hex:", 4u) != 0) return data;
    al_size digits = 0u;
    for (al_size i = 4u; i < size; ++i)
        if (fuzz_hex_digit(data[i]) >= 0) ++digits;
    if ((digits & 1u) != 0u) return data;
    al_u8 *decoded = (al_u8 *)malloc(digits / 2u);
    if (decoded == NULL && digits != 0u) return data;
    al_size out = 0u;
    int high = -1;
    for (al_size i = 4u; i < size; ++i) {
        int digit = fuzz_hex_digit(data[i]);
        if (digit < 0) continue;
        if (high < 0) high = digit;
        else {
            decoded[out++] = (al_u8)((high << 4) | digit);
            high = -1;
        }
    }
    *allocation = decoded;
    *normalized_size = out;
    return decoded;
}

int LLVMFuzzerTestOneInput(const al_u8 *data, al_size size);

#if !defined(AL_LIBFUZZER)
static int fuzz_run_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) return 1;
    (void)fseek(file, 0, SEEK_END);
    long length = ftell(file);
    (void)fseek(file, 0, SEEK_SET);
    if (length < 0 || (al_u64)length > UINT64_C(2097152)) {
        (void)fclose(file); return 1;
    }
    al_u8 *data = (al_u8 *)malloc((al_size)length);
    if (data == NULL && length != 0) { (void)fclose(file); return 1; }
    al_size read = fread(data, 1u, (al_size)length, file);
    (void)fclose(file);
    if (read != (al_size)length) { free(data); return 1; }
    (void)LLVMFuzzerTestOneInput(data, read);
    free(data);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int result = 0;
    for (int i = 1; i < argc; ++i) result |= fuzz_run_file(argv[i]);
    return result;
}
#endif

#endif /* ASTROLUNE_FUZZ_INPUT_H */
