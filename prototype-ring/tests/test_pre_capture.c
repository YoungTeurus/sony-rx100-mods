#include "pre_capture.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    pc_ring ring;
    pc_frame slots[8];
    uint32_t captures[64], released[64], writes[64], stop_tickets[64], write_tickets[64];
    size_t ncapture, nrelease, nwrite, nstop;
    uint32_t fail_release;
    bool fail_capture, fail_stop, fail_write, try_reentry;
    pc_result reentry;
} fixture;

static int capture(void *ctx, uint32_t ticket) {
    fixture *f = ctx;
    if (f->try_reentry) f->reentry = pc_trigger(&f->ring, 123);
    if (f->fail_capture) return 1;
    assert(f->ncapture < 64);
    f->captures[f->ncapture++] = ticket;
    return 0;
}
static int stop(void *ctx, uint32_t ticket) {
    fixture *f = ctx;
    assert(f->nstop < 64);
    f->stop_tickets[f->nstop++] = ticket;
    return f->fail_stop;
}
static int release(void *ctx, const pc_frame *frame) {
    fixture *f = ctx;
    if (f->fail_release == frame->lease) return 1;
    assert(f->nrelease < 64);
    f->released[f->nrelease++] = frame->lease;
    return 0;
}
static int write_frame(void *ctx, uint32_t ticket, const pc_frame *frame) {
    fixture *f = ctx;
    if (f->fail_write) return 1;
    assert(f->nwrite < 64);
    f->write_tickets[f->nwrite] = ticket;
    f->writes[f->nwrite++] = frame->lease;
    return 0;
}
static void init(fixture *f, uint32_t budget, uint32_t max_frame, size_t capacity) {
    memset(f, 0, sizeof(*f));
    pc_config config = {budget, max_frame, 50, true};
    pc_backend backend = {f, capture, stop, release, write_frame};
    assert(pc_init(&f->ring, config, backend, f->slots, capacity));
    assert(pc_arm(&f->ring) == PC_OK);
}
static pc_result deliver_at(fixture *f, uint32_t id, uint32_t bytes, uint64_t exposure_ns) {
    pc_frame frame = {id, bytes, exposure_ns, (void *)(uintptr_t)id};
    pc_result result = pc_frame_ready(&f->ring, f->ring.in_flight, &frame);
    assert(result == PC_REJECTED ? frame.lease == id : frame.lease == 0);
    return result;
}
static pc_result deliver(fixture *f, uint32_t id, uint32_t bytes) {
    return deliver_at(f, id, bytes, id * 100);
}
static void focus(fixture *f) { assert(pc_focus_ready(&f->ring) == PC_OK); }
static void finish_save(fixture *f) {
    assert(pc_stopped(&f->ring, f->ring.stop_ticket, true) == PC_OK);
    while (f->ring.state == PC_SAVING)
        assert(pc_write_complete(&f->ring, f->ring.writing_ticket, true) == PC_OK);
    assert(f->ring.state == PC_DONE && f->ring.count == 0 && f->ring.used_bytes == 0);
}

static void test_b_then_c_only_after_stop(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    assert(deliver(&f, 2, 100) == PC_OK);
    assert(f.nrelease == 1 && f.released[0] == 1 && f.nwrite == 0);
    assert(pc_trigger(&f.ring, 250) == PC_OK);
    assert(pc_cancel(&f.ring) == PC_IGNORED);
    assert(deliver(&f, 3, 100) == PC_OK);
    assert(f.nstop == 1 && f.nwrite == 0 && f.ring.state == PC_DRAIN);
    finish_save(&f);
    assert(f.nwrite == 2 && f.writes[0] == 2 && f.writes[1] == 3);
    assert(f.nrelease == 3 && f.released[1] == 2 && f.released[2] == 3);
    assert(f.ncapture == 3 && f.ring.written_frames == 2);
}

static void test_cancel_waits_for_inflight_outcome(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    assert(deliver(&f, 2, 100) == PC_OK);
    assert(pc_cancel(&f.ring) == PC_OK);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_OK);
    assert(f.ring.state == PC_CANCEL_DRAIN && f.ring.count == 1);
    assert(pc_capture_aborted(&f.ring, f.ring.in_flight) == PC_OK);
    assert(f.ring.state == PC_CANCELLED && f.nwrite == 0);
    assert(f.nrelease == 2 && f.released[1] == 2);
    assert(f.ring.used_bytes == 0 && f.ring.in_flight == 0);
}

static void test_cancel_accepts_last_frame(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    assert(pc_cancel(&f.ring) == PC_OK);
    assert(deliver(&f, 2, 100) == PC_OK);
    assert(f.ring.state == PC_CANCEL_DRAIN && f.nwrite == 0);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_OK);
    assert(f.ring.state == PC_CANCELLED && f.nrelease == 2);
}

static void test_variable_sizes_and_early_trigger(void) {
    fixture f; init(&f, 1000, 300, 8); focus(&f);
    assert(deliver(&f, 1, 200) == PC_OK);
    assert(deliver(&f, 2, 250) == PC_OK);
    assert(deliver(&f, 3, 200) == PC_OK);
    assert(f.ring.used_bytes == 450 && f.released[0] == 1);
    assert(pc_trigger(&f.ring, 350) == PC_OK);
    assert(deliver(&f, 4, 300) == PC_OK);
    assert(f.ring.used_bytes == 750 && f.ncapture == 4 && f.nwrite == 0);
    finish_save(&f);
    assert(f.nwrite == 3 && f.writes[0] == 2 && f.writes[1] == 3 && f.writes[2] == 4);

    init(&f, 200, 100, 2);
    assert(pc_trigger(&f.ring, 1) == PC_OK);
    assert(f.ncapture == 0 && f.ring.state == PC_WAIT_FOCUS);
    focus(&f);
    assert(deliver(&f, 5, 100) == PC_OK);
    assert(deliver(&f, 6, 100) == PC_OK);
    finish_save(&f);
    assert(f.writes[0] == 5 && f.writes[1] == 6);
}

static void test_stale_events_do_not_take_ownership(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    pc_frame stale = {7, 100, 700, NULL};
    assert(pc_frame_ready(&f.ring, 1, &stale) == PC_REJECTED && stale.lease == 7);
    assert(deliver(&f, 1, 100) == PC_REJECTED);
    assert(pc_write_complete(&f.ring, 1, true) == PC_REJECTED);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_REJECTED);
    assert(f.ring.count == 1 && f.nrelease == 0 && f.ring.in_flight == 2);
}

static void test_release_failure_keeps_both_owners(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    f.fail_release = 1;
    assert(deliver(&f, 2, 100) == PC_FAILED);
    assert(f.ring.state == PC_FAULT && f.ring.error == PC_RELEASE_ERROR);
    assert(f.ring.count == 1 && f.ring.frames[f.ring.head].lease == 1);
    assert(f.ring.staged.lease == 2 && f.nrelease == 0 && f.nwrite == 0);
    assert(f.ncapture == 2 && f.nstop == 1);
}

static void test_write_failure_keeps_owner(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    assert(pc_trigger(&f.ring, 150) == PC_OK);
    assert(deliver(&f, 2, 100) == PC_OK);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_OK);
    assert(pc_write_complete(&f.ring, 9, true) == PC_REJECTED);
    assert(pc_write_complete(&f.ring, f.ring.writing_ticket, false) == PC_FAILED);
    assert(f.ring.state == PC_FAULT && f.ring.error == PC_WRITE_ERROR);
    assert(f.ring.count == 2 && f.nrelease == 0 && f.nwrite == 1);
}

static void test_bad_frame_and_command_failures(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 101) == PC_FAILED);
    assert(f.ring.state == PC_FAULT && f.ring.staged.lease == 1 && f.nwrite == 0);
    init(&f, 200, 100, 2); f.fail_capture = true;
    assert(pc_focus_ready(&f.ring) == PC_FAILED && f.ring.in_flight == 0);
    init(&f, 200, 100, 2); focus(&f); f.fail_stop = true;
    assert(pc_cancel(&f.ring) == PC_FAILED && f.ring.state == PC_FAULT);
    assert(deliver(&f, 4, 100) == PC_FAILED && f.ring.staged.lease == 4);
    init(&f, 200, 100, 2); focus(&f); f.fail_write = true;
    assert(pc_trigger(&f.ring, 1) == PC_OK);
    assert(deliver(&f, 1, 100) == PC_OK && deliver(&f, 2, 100) == PC_OK);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_FAILED && f.ring.count == 2);
}

static void test_explicit_rearm_and_reentry(void) {
    fixture f; init(&f, 200, 100, 2); f.try_reentry = true; focus(&f);
    assert(f.reentry == PC_REJECTED && f.ring.state == PC_PRE);
    assert(pc_arm(&f.ring) == PC_REJECTED);
    assert(pc_cancel(&f.ring) == PC_OK);
    assert(pc_capture_aborted(&f.ring, f.ring.in_flight) == PC_OK);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_OK);
    assert(f.ncapture == 1);
    assert(pc_focus_ready(&f.ring) == PC_REJECTED);
    assert(pc_arm(&f.ring) == PC_OK);
    focus(&f);
    assert(f.captures[1] == 3);
}

static void test_invalid_budgets_and_disabled(void) {
    fixture f; init(&f, 200, 100, 2);
    pc_config bad = {200, 101, 50, true};
    assert(!pc_init(&f.ring, bad, f.ring.backend, f.slots, 2));
    bad = (pc_config){200, 100, 100, true};
    assert(!pc_init(&f.ring, bad, f.ring.backend, f.slots, 2));
    bad = (pc_config){200, 100, 50, false};
    assert(pc_init(&f.ring, bad, f.ring.backend, f.slots, 2));
    assert(pc_arm(&f.ring) == PC_IGNORED && f.ncapture == 0);
}

static void test_stale_completions_after_rearm(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver(&f, 1, 100) == PC_OK);
    assert(pc_trigger(&f.ring, 150) == PC_OK);
    assert(deliver(&f, 2, 100) == PC_OK);
    finish_save(&f);
    uint32_t old_stop = f.stop_tickets[0], old_write = f.write_tickets[0];
    assert(pc_arm(&f.ring) == PC_OK); focus(&f);
    assert(deliver_at(&f, 1, 100, 1100) == PC_OK);
    assert(pc_trigger(&f.ring, 1150) == PC_OK);
    assert(deliver_at(&f, 2, 100, 1200) == PC_OK);
    assert(pc_stopped(&f.ring, old_stop, true) == PC_REJECTED);
    assert(f.nwrite == 2 && f.nrelease == 2 && f.ring.state == PC_DRAIN);
    assert(pc_stopped(&f.ring, f.ring.stop_ticket, true) == PC_OK);
    assert(pc_write_complete(&f.ring, old_write, true) == PC_REJECTED);
    assert(f.nwrite == 3 && f.nrelease == 2 && f.ring.count == 2);
    assert(pc_write_complete(&f.ring, f.ring.writing_ticket, true) == PC_OK);
    assert(pc_write_complete(&f.ring, f.ring.writing_ticket, true) == PC_OK);
    assert(f.ring.state == PC_DONE && f.nwrite == 4 && f.nrelease == 4);
}

static void test_late_pre_exposure_is_not_post(void) {
    fixture f; init(&f, 200, 100, 2); focus(&f);
    assert(deliver_at(&f, 1, 100, UINT64_C(0xfffffff0)) == PC_OK);
    assert(pc_trigger(&f.ring, UINT64_C(0x100000010)) == PC_OK);
    assert(deliver_at(&f, 2, 100, UINT64_C(0xffffffff)) == PC_OK);
    assert(f.ring.count == 1 && f.nstop == 0 && f.ncapture == 3);
    assert(f.nrelease == 1 && f.released[0] == 2 && f.nwrite == 0);
    assert(deliver_at(&f, 3, 100, UINT64_C(0x100000020)) == PC_OK);
    finish_save(&f);
    assert(f.nwrite == 2 && f.writes[0] == 1 && f.writes[1] == 3);
}

int main(void) {
    test_b_then_c_only_after_stop();
    test_cancel_waits_for_inflight_outcome();
    test_cancel_accepts_last_frame();
    test_variable_sizes_and_early_trigger();
    test_stale_events_do_not_take_ownership();
    test_release_failure_keeps_both_owners();
    test_write_failure_keeps_owner();
    test_bad_frame_and_command_failures();
    test_explicit_rearm_and_reentry();
    test_invalid_budgets_and_disabled();
    test_stale_completions_after_rearm();
    test_late_pre_exposure_is_not_post();
    puts("PASS: 12 retained-ring scenario groups");
    return 0;
}
