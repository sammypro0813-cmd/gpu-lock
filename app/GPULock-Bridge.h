/* C interface of core/src/lib.rs (libgpulock_core.a). Keep the two in step. */
#ifndef GPULOCK_BRIDGE_H
#define GPULOCK_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

/* Every returned char* (results and errors) is freed with gl_string_free. */
void gl_string_free(char *s);

typedef void (*GlLogCallback)(const char *message, void *context);
void gl_set_log_callback(GlLogCallback callback, void *context);

/* ---- On-device pairing (iOS 27+) ---- */
typedef struct GlPairing GlPairing;
typedef void (*GlPinCallback)(const char *pin, void *context);

GlPairing *gl_pairing_new(const char *name, char **error);
uint16_t gl_pairing_port(const GlPairing *s);
const char *gl_pairing_service_name(const GlPairing *s);
size_t gl_pairing_txt_count(const GlPairing *s);
const char *gl_pairing_txt_key(const GlPairing *s, size_t index);
const char *gl_pairing_txt_value(const GlPairing *s, size_t index);
/* Blocks. 0 paired (file written to out_path), 1 failed (*error), 2 cancelled. */
int32_t gl_pairing_accept(const GlPairing *s, GlPinCallback pin_callback, void *pin_context,
                          const char *out_path, char **out_device_name, char **error);
void gl_pairing_cancel(const GlPairing *s);
void gl_pairing_free(GlPairing *s);

/* ---- Session (all calls block; never call on the main thread) ---- */
/* Returns the condition list as JSON, or NULL with *error set. */
char *gl_start(const char *ip, uint16_t port, const char *pairing_path,
               const char *hostname, const char *ddi_dir, char **error);
int32_t gl_enable(const char *group, const char *profile, char **error);
int32_t gl_disable(char **error);
char *gl_refresh(char **error);
void gl_stop(void);

#endif
