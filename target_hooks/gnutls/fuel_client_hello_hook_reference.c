/*
 * Reference copy of the FuEL GnuTLS generator-side ClientHello hook.
 *
 * The real build flow injects equivalent logic into gnutls/lib/handshake.c.
 * This reference file exists only to make code review and slide linking
 * practical after uploading the hook package to a separate repository.
 */

#ifdef FT_GENERATOR
unsigned fuel_emitted_messages = 0;

static unsigned fuel_gnutls_read_uint16(const uint8_t *data)
{
    return ((unsigned)data[0] << 8) | (unsigned)data[1];
}

static unsigned fuel_gnutls_read_uint24(const uint8_t *data)
{
    return ((unsigned)data[0] << 16) | ((unsigned)data[1] << 8)
           | (unsigned)data[2];
}

static int fuel_gnutls_trace_enabled(void)
{
    static int initialized = 0;
    static int enabled = 0;
    const char *value;

    if (initialized != 0)
        return enabled;

    value = getenv("FUEL_GNUTLS_TRACE");
    enabled = value != NULL && value[0] != '\0' && value[0] != '0';
    initialized = 1;

    return enabled;
}

static unsigned long long fuel_gnutls_hash_bytes(const uint8_t *data,
                                                 size_t len)
{
    unsigned long long hash = 1469598103934665603ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= (unsigned long long)data[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

static int fuel_parse_client_hello(const uint8_t *msg, size_t msg_len,
                                   const uint8_t **session_id,
                                   size_t *session_id_len,
                                   const uint8_t **extensions,
                                   size_t *extensions_len)
{
    const uint8_t *payload;
    size_t payload_len;
    size_t offset;
    size_t sid_len;
    size_t cipher_suites_len;
    size_t compression_methods_len;
    size_t ext_len;

    if (msg == NULL || msg_len < 4
        || msg[0] != GNUTLS_HANDSHAKE_CLIENT_HELLO)
        return 0;

    payload_len = fuel_gnutls_read_uint24(&msg[1]);
    if (payload_len + 4 != msg_len || payload_len < 34)
        return 0;

    payload = msg + 4;
    offset = 34;

    sid_len = payload[offset];
    offset += 1;
    if (offset + sid_len + 2 > payload_len)
        return 0;

    if (session_id != NULL)
        *session_id = payload + offset;
    if (session_id_len != NULL)
        *session_id_len = sid_len;
    offset += sid_len;

    cipher_suites_len = fuel_gnutls_read_uint16(payload + offset);
    offset += 2;
    if ((cipher_suites_len & 1) != 0
        || offset + cipher_suites_len + 1 > payload_len)
        return 0;
    offset += cipher_suites_len;

    compression_methods_len = payload[offset];
    offset += 1;
    if (offset + compression_methods_len > payload_len)
        return 0;
    offset += compression_methods_len;

    if (offset == payload_len) {
        if (extensions != NULL)
            *extensions = NULL;
        if (extensions_len != NULL)
            *extensions_len = 0;
        return 1;
    }

    if (offset + 2 > payload_len)
        return 0;

    ext_len = fuel_gnutls_read_uint16(payload + offset);
    offset += 2;
    if (offset + ext_len != payload_len)
        return 0;

    if (extensions != NULL)
        *extensions = payload + offset;
    if (extensions_len != NULL)
        *extensions_len = ext_len;

    return 1;
}

static int fuel_find_client_hello_extension(const uint8_t *msg, size_t msg_len,
                                            unsigned ext_type,
                                            const uint8_t **ext_data,
                                            size_t *ext_len)
{
    const uint8_t *extensions;
    size_t extensions_len;
    size_t offset = 0;

    if (!fuel_parse_client_hello(msg, msg_len, NULL, NULL, &extensions,
                                 &extensions_len)
        || extensions == NULL)
        return 0;

    while (offset + 4 <= extensions_len) {
        unsigned current_type;
        size_t current_len;

        current_type = fuel_gnutls_read_uint16(extensions + offset);
        current_len = fuel_gnutls_read_uint16(extensions + offset + 2);
        offset += 4;

        if (offset + current_len > extensions_len)
            return 0;

        if (current_type == ext_type) {
            if (ext_data != NULL)
                *ext_data = extensions + offset;
            if (ext_len != NULL)
                *ext_len = current_len;
            return 1;
        }

        offset += current_len;
    }

    return 0;
}

static void fuel_trace_client_hello_summary(const char *stage,
                                            const uint8_t *msg, size_t msg_len)
{
    const uint8_t *extensions;
    const uint8_t *payload;
    const uint8_t *ext_data;
    size_t extensions_len = 0;
    size_t session_id_len = 0;
    size_t cipher_suites_len;
    size_t compression_methods_len;
    size_t offset;
    size_t ext_len;
    size_t server_name_len = 0;
    size_t supported_groups_len = 0;
    size_t signature_algorithms_len = 0;
    size_t supported_versions_len = 0;
    size_t key_share_len = 0;
    unsigned long long hash;

    if (!fuel_gnutls_trace_enabled())
        return;

    hash = fuel_gnutls_hash_bytes(msg, msg_len);

    if (!fuel_parse_client_hello(msg, msg_len, NULL, &session_id_len,
                                 &extensions, &extensions_len)) {
        fprintf(stderr,
                "[FuEL][gnutls][trace] stage=%s invalid_client_hello len=%lu hash=%llx\n",
                stage, (unsigned long)msg_len, hash);
        fflush(stderr);
        return;
    }

    payload = msg + 4;
    offset = 34 + 1 + session_id_len;
    cipher_suites_len = fuel_gnutls_read_uint16(payload + offset);
    offset += 2 + cipher_suites_len;
    compression_methods_len = payload[offset];

    if (fuel_find_client_hello_extension(msg, msg_len, 0x0000, &ext_data,
                                         &ext_len))
        server_name_len = ext_len;
    if (fuel_find_client_hello_extension(msg, msg_len, 0x000a, &ext_data,
                                         &ext_len))
        supported_groups_len = ext_len;
    if (fuel_find_client_hello_extension(msg, msg_len, 0x000d, &ext_data,
                                         &ext_len))
        signature_algorithms_len = ext_len;
    if (fuel_find_client_hello_extension(msg, msg_len, 0x002b, &ext_data,
                                         &ext_len))
        supported_versions_len = ext_len;
    if (fuel_find_client_hello_extension(msg, msg_len, 0x0033, &ext_data,
                                         &ext_len))
        key_share_len = ext_len;

    fprintf(stderr,
            "[FuEL][gnutls][trace] stage=%s len=%lu sid=%lu cs=%lu comp=%lu ext=%lu sni=%lu groups=%lu sigalgs=%lu versions=%lu keyshare=%lu hash=%llx\n",
            stage,
            (unsigned long)msg_len,
            (unsigned long)session_id_len,
            (unsigned long)cipher_suites_len,
            (unsigned long)compression_methods_len,
            (unsigned long)extensions_len,
            (unsigned long)server_name_len,
            (unsigned long)supported_groups_len,
            (unsigned long)signature_algorithms_len,
            (unsigned long)supported_versions_len,
            (unsigned long)key_share_len,
            hash);
    fflush(stderr);
}

static void fuel_sync_client_hello_session_id(gnutls_session_t session,
                                              const uint8_t *msg,
                                              size_t msg_len)
{
    const uint8_t *session_id;
    size_t session_id_len;

    if (!fuel_parse_client_hello(msg, msg_len, &session_id, &session_id_len,
                                 NULL, NULL)
        || session_id_len > GNUTLS_MAX_SESSION_ID_SIZE)
        return;

    if (session_id_len > 0)
        memcpy(session->security_parameters.session_id, session_id,
               session_id_len);
    session->security_parameters.session_id_size = session_id_len;
}

static void fuel_restore_client_hello_key_share(uint8_t *msg, size_t msg_len,
                                                const uint8_t *original_msg,
                                                size_t original_len)
{
    const uint8_t *original_key_share;
    const uint8_t *mutated_key_share;
    size_t original_key_share_len;
    size_t mutated_key_share_len;

    if (msg == NULL || original_msg == NULL)
        return;

    if (!fuel_find_client_hello_extension(original_msg, original_len, 0x0033,
                                          &original_key_share,
                                          &original_key_share_len))
        return;

    if (!fuel_find_client_hello_extension(msg, msg_len, 0x0033,
                                          &mutated_key_share,
                                          &mutated_key_share_len))
        return;

    if (original_key_share_len != mutated_key_share_len)
        return;

    memcpy((uint8_t *)mutated_key_share, original_key_share,
           original_key_share_len);
}

static void fuel_mutate_client_hello(gnutls_session_t session, uint8_t *data,
                                     uint32_t datasize)
{
    struct shared_buffer buffer;
    uint8_t original[BUFFER_SIZE];

    if (data == NULL || datasize < 4 || datasize > BUFFER_SIZE)
        return;

    memcpy(original, data, datasize);
    fuel_trace_client_hello_summary("pre_mutation", original, datasize);

    memset(&buffer, 0, sizeof(buffer));
    buffer.type = GNUTLS_HANDSHAKE_CLIENT_HELLO;
    buffer.len = (uint16_t)datasize;
    memcpy(buffer.data, data, datasize);

    fuzz_plaintext(&buffer);

    if (buffer.len >= datasize) {
        memcpy(data, buffer.data, datasize);
    } else {
        memcpy(data, buffer.data, buffer.len);
        memset(data + buffer.len, 0, datasize - buffer.len);
    }

    data[0] = GNUTLS_HANDSHAKE_CLIENT_HELLO;
    _gnutls_write_uint24(datasize - 4, &data[1]);
    fuel_trace_client_hello_summary("post_fuzz_pre_repair", data, datasize);

    fuel_restore_client_hello_key_share(data, datasize, original, datasize);
    fuel_sync_client_hello_session_id(session, data, datasize);
    fuel_trace_client_hello_summary("post_repair", data, datasize);
    fuel_emitted_messages++;
}
#endif
