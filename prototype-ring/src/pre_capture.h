#ifndef PRE_CAPTURE_H
#define PRE_CAPTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PC_IDLE, PC_WAIT_FOCUS, PC_PRE, PC_POST, PC_DRAIN, PC_CANCEL_DRAIN,
    PC_SAVING, PC_DONE, PC_CANCELLED, PC_FAULT
} pc_state;

typedef enum { PC_OK, PC_IGNORED, PC_REJECTED, PC_FAILED } pc_result;
typedef enum {
    PC_NO_ERROR, PC_CAPTURE_ERROR, PC_STOP_ERROR, PC_RELEASE_ERROR,
    PC_WRITE_ERROR, PC_FRAME_TOO_LARGE, PC_TICKET_EXHAUSTED
} pc_error;

typedef struct {
    uint32_t lease;
    uint32_t allocation_bytes;
    uint64_t exposure_ns; /* same monotonic clock as the physical trigger */
    void *handle;
} pc_frame;

typedef struct {
    uint32_t storage_bytes;
    uint32_t max_frame_bytes;
    unsigned pre_percent;
    bool enabled;
} pc_config;

/* Command callbacks enqueue work without reentry. Release returns 0 only when
 * this exact proven lease is relinquished; an uncertain acquire is not a lease.
 * Write completion means durable file completion, not accepted submission. */
typedef struct {
    void *context;
    int (*capture)(void *, uint32_t ticket);
    int (*stop)(void *, uint32_t ticket);
    int (*release)(void *, const pc_frame *);
    int (*write)(void *, uint32_t ticket, const pc_frame *);
} pc_backend;

typedef struct {
    pc_config config;
    pc_backend backend;
    pc_frame *frames;
    size_t capacity, head, count;
    pc_frame staged;
    uint32_t used_bytes, pre_bytes, next_ticket, in_flight, writing_lease;
    uint32_t stop_ticket, writing_ticket;
    uint32_t written_frames;
    uint64_t trigger_ns;
    pc_state state;
    pc_error error;
    bool stop_sent, stop_acked, in_callback, trigger_latched;
} pc_ring;

/* storage_bytes excludes a separately reserved max_frame_bytes staging slot
 * and the producer's working memory. Calls/events must be serialized.
 * Init once per event subscription; detach old sources before reinitializing. */
bool pc_init(pc_ring *, pc_config, pc_backend, pc_frame *slots, size_t capacity);
pc_result pc_arm(pc_ring *);
pc_result pc_focus_ready(pc_ring *);
pc_result pc_trigger(pc_ring *, uint64_t timestamp_ns);
pc_result pc_cancel(pc_ring *);
/* PC_OK or PC_FAILED consumes frame and clears frame->lease; PC_REJECTED
 * leaves ownership with the caller. A fault keeps every unreleased owner. */
pc_result pc_frame_ready(pc_ring *, uint32_t ticket, pc_frame *frame);
pc_result pc_capture_aborted(pc_ring *, uint32_t ticket);
pc_result pc_stopped(pc_ring *, uint32_t stop_ticket, bool success);
pc_result pc_write_complete(pc_ring *, uint32_t write_ticket, bool success);

#endif
