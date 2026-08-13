#ifndef MST5_CLIENT_H
#define MST5_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(MST5_BUILDING_DLL)
#    define MST5_API __declspec(dllexport)
#  else
#    define MST5_API __declspec(dllimport)
#  endif
#else
#  define MST5_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MST5_ABI_VERSION 1u
#define MST5_OK 0
#define MST5_ERROR_INVALID_ARGUMENT 1
#define MST5_ERROR_IO 2
#define MST5_ERROR_NOT_FOUND 3
#define MST5_ERROR_PANIC 255

typedef uint64_t mst5_client_t;
typedef uint64_t mst5_identity_t;

typedef struct mst5_buffer {
    uint8_t *data;
    size_t len;
} mst5_buffer;

MST5_API uint32_t mst5_abi_version(void);
MST5_API const char *mst5_version(void);
MST5_API const char *mst5_last_error(void);
MST5_API void mst5_buffer_free(mst5_buffer buffer);

MST5_API int32_t mst5_client_connect(const char *endpoint, const char *server_public_key_b64,
                                     mst5_client_t *out_client);
MST5_API int32_t mst5_client_connect_compiled(const char *endpoint,
                                              mst5_client_t *out_client);
MST5_API int32_t mst5_client_authenticate(mst5_client_t client, const char *token);
MST5_API int32_t mst5_client_request(mst5_client_t client, uint8_t kind, uint16_t opcode,
                                     const uint8_t *payload, size_t payload_len,
                                     uint64_t deadline_ms, mst5_buffer *out_response);
MST5_API int32_t mst5_client_close(mst5_client_t client);

MST5_API int32_t mst5_identity_open(const char *private_store_path, int32_t create,
                                    mst5_identity_t *out_identity);
MST5_API int32_t mst5_identity_restore(const char *private_store_path, const char *password,
                                       const uint8_t *backup, size_t backup_len,
                                       mst5_identity_t *out_identity);
MST5_API int32_t mst5_identity_remove(const char *private_store_path);
MST5_API int32_t mst5_identity_close(mst5_identity_t identity);
MST5_API int32_t mst5_identity_public_key(mst5_identity_t identity, mst5_buffer *out_key);
MST5_API int32_t mst5_identity_fingerprint(mst5_identity_t identity, mst5_buffer *out_text);
MST5_API int32_t mst5_e2e_seal(mst5_identity_t identity, const uint8_t peer_public_key[32],
                               const char *from_id, const char *to_id,
                               const uint8_t *plaintext, size_t plaintext_len,
                               mst5_buffer *out_envelope);
MST5_API int32_t mst5_e2e_open(mst5_identity_t identity, const uint8_t peer_public_key[32],
                               const char *from_id, const char *to_id,
                               const uint8_t *envelope, size_t envelope_len,
                               mst5_buffer *out_plaintext);
MST5_API int32_t mst5_e2e_backup(mst5_identity_t identity, const char *password,
                                 mst5_buffer *out_backup);

#ifdef __cplusplus
}
#endif
#endif
