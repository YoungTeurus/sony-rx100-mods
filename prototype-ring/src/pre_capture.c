#include "pre_capture.h"

static bool callable(const pc_ring *r) { return r && !r->in_callback; }

static size_t next_slot(const pc_ring *r, size_t index) {
    return index + 1 == r->capacity ? 0 : index + 1;
}

static size_t tail_slot(const pc_ring *r) {
    size_t until_wrap = r->capacity - r->head;
    return r->count < until_wrap ? r->head + r->count : r->count - until_wrap;
}

static uint32_t take_ticket(pc_ring *r) {
    if (r->next_ticket == UINT32_MAX) {
        r->state = PC_FAULT;
        r->error = PC_TICKET_EXHAUSTED;
        return 0;
    }
    return ++r->next_ticket;
}

static pc_result request_stop(pc_ring *r) {
    if (r->stop_sent) return PC_OK;
    r->stop_ticket = take_ticket(r);
    if (!r->stop_ticket) return PC_FAILED;
    r->stop_sent = true;
    r->in_callback = true;
    int result = r->backend.stop(r->backend.context, r->stop_ticket);
    r->in_callback = false;
    if (result) {
        if (r->error == PC_NO_ERROR) r->error = PC_STOP_ERROR;
        r->state = PC_FAULT;
        return PC_FAILED;
    }
    return PC_OK;
}

static pc_result fault(pc_ring *r, pc_error error) {
    r->error = error;
    r->state = PC_FAULT;
    request_stop(r);
    return PC_FAILED;
}

static bool relinquish(pc_ring *r, pc_frame *frame) {
    r->in_callback = true;
    int result = r->backend.release(r->backend.context, frame);
    r->in_callback = false;
    if (result) {
        fault(r, PC_RELEASE_ERROR);
        return false;
    }
    frame->lease = 0;
    return true;
}

static bool release_head(pc_ring *r) {
    pc_frame *frame = &r->frames[r->head];
    uint32_t bytes = frame->allocation_bytes;
    if (!relinquish(r, frame)) return false;
    r->used_bytes -= bytes;
    r->head = next_slot(r, r->head);
    r->count--;
    return true;
}

static pc_result request_capture(pc_ring *r) {
    r->in_flight = take_ticket(r);
    if (!r->in_flight) return PC_FAILED;
    r->in_callback = true;
    int result = r->backend.capture(r->backend.context, r->in_flight);
    r->in_callback = false;
    if (result) {
        r->in_flight = 0;
        return fault(r, PC_CAPTURE_ERROR);
    }
    return PC_OK;
}

static pc_result request_write(pc_ring *r) {
    if (!r->count) {
        r->state = PC_DONE;
        return PC_OK;
    }
    const pc_frame *frame = &r->frames[r->head];
    r->writing_ticket = take_ticket(r);
    if (!r->writing_ticket) return PC_FAILED;
    r->writing_lease = frame->lease;
    r->in_callback = true;
    int result = r->backend.write(r->backend.context, r->writing_ticket, frame);
    r->in_callback = false;
    if (result) {
        r->writing_lease = 0;
        r->writing_ticket = 0;
        return fault(r, PC_WRITE_ERROR);
    }
    return PC_OK;
}

static pc_result finish_drain(pc_ring *r) {
    if (!r->stop_acked || r->in_flight) return PC_OK;
    if (r->state == PC_CANCEL_DRAIN) {
        while (r->count) if (!release_head(r)) return PC_FAILED;
        r->state = PC_CANCELLED;
    } else if (r->state == PC_DRAIN) {
        r->state = PC_SAVING;
        return request_write(r);
    }
    return r->state == PC_FAULT ? PC_FAILED : PC_OK;
}

bool pc_init(pc_ring *r, pc_config config, pc_backend backend,
             pc_frame *slots, size_t capacity) {
    if (!r || !slots || capacity < 2 || !backend.capture || !backend.stop ||
        !backend.release || !backend.write || !config.max_frame_bytes ||
        !config.pre_percent || config.pre_percent >= 100) return false;
    uint32_t pre = (config.storage_bytes / 100) * config.pre_percent +
                   (config.storage_bytes % 100) * config.pre_percent / 100;
    if (pre < config.max_frame_bytes ||
        config.storage_bytes - pre < config.max_frame_bytes) return false;
    /* The injectable controller cannot depend on a process-global C runtime. */
    volatile unsigned char *bytes = (volatile unsigned char *)r;
    for (size_t i = 0; i < sizeof(*r); i++) bytes[i] = 0;
    r->config = config;
    r->backend = backend;
    r->frames = slots;
    r->capacity = capacity;
    r->pre_bytes = pre;
    r->state = PC_IDLE;
    for (size_t i = 0; i < capacity; i++) slots[i].lease = 0;
    return true;
}

pc_result pc_arm(pc_ring *r) {
    if (!callable(r)) return PC_REJECTED;
    if (!r->config.enabled) return PC_IGNORED;
    if ((r->state != PC_IDLE && r->state != PC_DONE && r->state != PC_CANCELLED) ||
        r->count || r->staged.lease || r->in_flight || r->writing_lease) return PC_REJECTED;
    r->state = PC_WAIT_FOCUS;
    r->error = PC_NO_ERROR;
    r->stop_sent = r->stop_acked = false;
    r->trigger_latched = false;
    r->stop_ticket = r->writing_ticket = 0;
    r->written_frames = 0;
    r->trigger_ns = 0;
    return PC_OK;
}

pc_result pc_focus_ready(pc_ring *r) {
    if (!callable(r) || r->state != PC_WAIT_FOCUS) return PC_REJECTED;
    r->state = r->trigger_latched ? PC_POST : PC_PRE;
    return request_capture(r);
}

pc_result pc_trigger(pc_ring *r, uint64_t timestamp_ns) {
    if (!callable(r)) return PC_REJECTED;
    if (r->state == PC_POST || r->state == PC_DRAIN || r->state == PC_SAVING)
        return PC_IGNORED;
    if (r->state != PC_PRE && r->state != PC_WAIT_FOCUS) return PC_REJECTED;
    if (r->trigger_latched) return PC_IGNORED;
    r->trigger_latched = true;
    r->trigger_ns = timestamp_ns;
    if (r->state == PC_WAIT_FOCUS) return PC_OK;
    r->state = PC_POST;
    return r->in_flight ? PC_OK : request_capture(r);
}

pc_result pc_cancel(pc_ring *r) {
    if (!callable(r)) return PC_REJECTED;
    if (r->state == PC_POST || r->state == PC_DRAIN || r->state == PC_SAVING ||
        r->state == PC_DONE) return PC_IGNORED;
    if (r->state == PC_CANCEL_DRAIN || r->state == PC_CANCELLED) return PC_IGNORED;
    if (r->trigger_latched) return PC_IGNORED;
    if (r->state == PC_WAIT_FOCUS) {
        r->state = PC_CANCELLED;
        return PC_OK;
    }
    if (r->state != PC_PRE) return PC_REJECTED;
    r->state = PC_CANCEL_DRAIN;
    if (request_stop(r) != PC_OK) return PC_FAILED;
    return finish_drain(r);
}

pc_result pc_frame_ready(pc_ring *r, uint32_t ticket, pc_frame *frame) {
    if (!callable(r) || !frame || !frame->lease || !ticket ||
        ticket != r->in_flight || r->staged.lease) return PC_REJECTED;
    size_t index = r->head;
    for (size_t i = 0; i < r->count; i++, index = next_slot(r, index))
        if (r->frames[index].lease == frame->lease)
            return PC_REJECTED;
    if (r->state != PC_PRE && r->state != PC_POST &&
        r->state != PC_CANCEL_DRAIN && r->state != PC_FAULT) return PC_REJECTED;
    r->staged = *frame;
    frame->lease = 0;
    r->in_flight = 0;
    if (r->state == PC_FAULT) return PC_FAILED;
    if (r->state == PC_CANCEL_DRAIN) {
        if (!relinquish(r, &r->staged)) return PC_FAILED;
        return finish_drain(r);
    }
    uint32_t bytes = r->staged.allocation_bytes;
    if (!bytes || bytes > r->config.max_frame_bytes) return fault(r, PC_FRAME_TOO_LARGE);
    if (r->state == PC_POST && r->staged.exposure_ns < r->trigger_ns) {
        /* A late delivery cannot replace the frozen history or count as a new
         * post-trigger exposure. Keep the reserved slot for a later capture. */
        if (!relinquish(r, &r->staged)) return PC_FAILED;
        return request_capture(r);
    }
    if (r->state == PC_PRE) {
        while (r->count && (r->count >= r->capacity - 1 || r->used_bytes > r->pre_bytes - bytes))
            if (!release_head(r)) return PC_FAILED;
    } else if (r->count == r->capacity || bytes > r->config.storage_bytes - r->used_bytes) {
        return fault(r, PC_FRAME_TOO_LARGE);
    }
    r->frames[tail_slot(r)] = r->staged;
    r->staged.lease = 0;
    r->count++;
    r->used_bytes += bytes;
    if (r->state == PC_PRE || (r->count < r->capacity &&
        r->config.max_frame_bytes <= r->config.storage_bytes - r->used_bytes))
        return request_capture(r);
    r->state = PC_DRAIN;
    if (request_stop(r) != PC_OK) return PC_FAILED;
    return finish_drain(r);
}

pc_result pc_capture_aborted(pc_ring *r, uint32_t ticket) {
    if (!callable(r) || !ticket || ticket != r->in_flight) return PC_REJECTED;
    r->in_flight = 0;
    if (r->state == PC_FAULT) return PC_FAILED;
    if (r->state != PC_CANCEL_DRAIN) return fault(r, PC_CAPTURE_ERROR);
    return finish_drain(r);
}

pc_result pc_stopped(pc_ring *r, uint32_t ticket, bool success) {
    if (!callable(r) || !ticket || ticket != r->stop_ticket ||
        !r->stop_sent || r->stop_acked) return PC_REJECTED;
    if (!success) return fault(r, PC_STOP_ERROR);
    r->stop_acked = true;
    return finish_drain(r);
}

pc_result pc_write_complete(pc_ring *r, uint32_t ticket, bool success) {
    if (!callable(r) || r->state != PC_SAVING || !ticket ||
        ticket != r->writing_ticket) return PC_REJECTED;
    r->writing_lease = 0;
    r->writing_ticket = 0;
    if (!success) return fault(r, PC_WRITE_ERROR);
    r->written_frames++;
    if (!release_head(r)) return PC_FAILED;
    return request_write(r);
}
