/* Human-readable address text: Bech32 (BIP-173) with the "al" prefix.
 *
 *   al1qqsyxzs5z6gh8w7rr60pm4j7e00nvwtcr9vn9k3efjvwcg3uqsjs58glr6y
 *
 * Bech32 is checksummed and copy-paste safe; raw hex is not. Addresses live
 * as 32 raw bytes everywhere consensus touches them - this encoding exists
 * only at the edges users see: CLI output, genesis authoring and RPC.
 *
 * Decode verifies the Bech32 checksum and rejects uppercase input outright:
 * a mixed-case string is a typo, not a format.
 */

#include "astrolune/crypto.h"
#include "internal/common.h"

#include <string.h>

#define ADDRESS_TEXT_HRP      "al"
#define ADDRESS_TEXT_CHARSET  "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
#define ADDRESS_TEXT_CONST    1u
#define ADDRESS_TEXT_CHECKSUM 6u

static al_u32 address_text_polymod(const al_u8 *symbols, al_size count) {
    static const al_u32 generator[5] = { 0x3b6a57b2u, 0x26508e6du,
                                         0x1ea119fau, 0x3d4233ddu,
                                         0x2a1462b3u };
    al_u32 chk = 1u;
    for (al_size i = 0u; i < count; ++i) {
        al_u32 top = chk >> 25u;
        chk = ((chk & 0x1ffffffu) << 5u) ^ symbols[i];
        for (al_size j = 0u; j < 5u; ++j)
            if ((top >> j) & 1u) chk ^= generator[j];
    }
    return chk;
}

/* hrp || [0] || lowercase(hrp): the prefix the checksum specification
 * requires before every polymod pass. */
static void address_text_hrp_prefix(al_u8 *out) {
    const char *hrp = ADDRESS_TEXT_HRP;
    al_size length = strlen(hrp);
    for (al_size i = 0u; i < length; ++i) out[i] = (al_u8)(hrp[i] >> 5);
    out[length] = 0u;
    for (al_size i = 0u; i < length; ++i)
        out[length + 1u + i] = (al_u8)(((unsigned)(unsigned char)hrp[i]) & 31u);
}

static int address_text_symbol_value(char c, al_u8 *value) {
    const char *table = ADDRESS_TEXT_CHARSET;
    for (const char *p = table; *p != '\0'; ++p) {
        if (*p == c) {
            *value = (al_u8)(p - table);
            return 1;
        }
    }
    return 0;
}

al_status al_address_to_bech32(const al_address *address, char *out,
                               al_size cap) {
    if (address == NULL || out == NULL) return AL_ERR_INVALID_ARG;

    /* 32 bytes -> 52 five-bit groups plus one padded group. */
    al_u8 payload[53];
    al_u32 accumulator = 0u;
    unsigned bits = 0u;
    al_size count = 0u;
    for (al_size i = 0u; i < AL_ADDRESS_SIZE; ++i) {
        accumulator = (accumulator << 8u) | address->bytes[i];
        bits += 8u;
        while (bits >= 5u) {
            bits -= 5u;
            payload[count++] = (al_u8)((accumulator >> bits) & 31u);
        }
    }
    payload[count++] = (al_u8)((accumulator << (5u - bits)) & 31u);

    al_u8 polymod_input[256];
    address_text_hrp_prefix(polymod_input);
    al_size input_length = strlen(ADDRESS_TEXT_HRP) * 2u + 1u;
    memcpy(polymod_input + input_length, payload, count);
    input_length += count;
    memset(polymod_input + input_length, 0, ADDRESS_TEXT_CHECKSUM);
    input_length += ADDRESS_TEXT_CHECKSUM;

    al_u32 polymod =
        address_text_polymod(polymod_input, input_length) ^
        ADDRESS_TEXT_CONST;

    al_size needed = strlen(ADDRESS_TEXT_HRP) + 1u + count +
                     ADDRESS_TEXT_CHECKSUM + 1u;
    if (cap < needed) return AL_ERR_BUFFER_TOO_SMALL;

    al_size pos = 0u;
    memcpy(out, ADDRESS_TEXT_HRP, strlen(ADDRESS_TEXT_HRP));
    pos += strlen(ADDRESS_TEXT_HRP);
    out[pos++] = '1';
    for (al_size i = 0u; i < count; ++i)
        out[pos++] = ADDRESS_TEXT_CHARSET[payload[i]];
    for (al_size i = 0u; i < ADDRESS_TEXT_CHECKSUM; ++i) {
        out[pos++] =
            ADDRESS_TEXT_CHARSET[(polymod >> (5u * (5u - i))) & 31u];
    }
    out[pos] = '\0';
    return AL_OK;
}

al_status al_address_from_bech32(const char *text, al_address *out) {
    if (text == NULL || out == NULL) return AL_ERR_INVALID_ARG;

    al_size length = strlen(text);
    if (length < 9u || length > 128u) return AL_ERR_INVALID_ARG;
    for (al_size i = 0u; i < length; ++i) {
        if (text[i] < '!' || text[i] > '~') return AL_ERR_MALFORMED;
        if (text[i] >= 'A' && text[i] <= 'Z') return AL_ERR_MALFORMED;
    }

    /* The separator is the LAST '1'; the HRP contains none itself. */
    const char *separator = strrchr(text, '1');
    if (separator == NULL) return AL_ERR_MALFORMED;
    al_size hrp_length = (al_size)(separator - text);
    if (hrp_length != (int)strlen(ADDRESS_TEXT_HRP) ||
        strncmp(text, ADDRESS_TEXT_HRP, hrp_length) != 0)
        return AL_ERR_MALFORMED;

    const char *payload_text = separator + 1u;
    al_size payload_length = length - hrp_length - 1u;
    if (payload_length <= ADDRESS_TEXT_CHECKSUM) return AL_ERR_MALFORMED;

    al_u8 symbols[128];
    for (al_size i = 0u; i < payload_length; ++i) {
        al_u8 value = 0u;
        if (!address_text_symbol_value(payload_text[i], &value))
            return AL_ERR_MALFORMED;
        symbols[i] = value;
    }

    al_u8 polymod_input[256];
    address_text_hrp_prefix(polymod_input);
    memcpy(polymod_input + 5u, symbols, payload_length);
    if (address_text_polymod(polymod_input, 5u + payload_length) !=
        ADDRESS_TEXT_CONST)
        return AL_ERR_CHECKSUM;

    /* 5-bit groups back to bytes, ignoring the six checksum groups and the
     * zero padding of the final group. */
    al_u32 accumulator = 0u;
    unsigned bits = 0u;
    al_size byte_count = 0u;
    for (al_size i = 0u; i < payload_length - ADDRESS_TEXT_CHECKSUM; ++i) {
        accumulator = (accumulator << 5u) | symbols[i];
        bits += 5u;
        while (bits >= 8u) {
            bits -= 8u;
            if (byte_count >= AL_ADDRESS_SIZE) return AL_ERR_OUT_OF_RANGE;
            out->bytes[byte_count++] = (al_u8)((accumulator >> bits) & 255u);
        }
    }
    if (byte_count != AL_ADDRESS_SIZE ||
        (accumulator & ((1u << bits) - 1u)) != 0u)
        return AL_ERR_MALFORMED;
    return AL_OK;
}
