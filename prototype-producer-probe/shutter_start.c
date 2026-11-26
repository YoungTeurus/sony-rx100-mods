struct sd_start_command {
    s32 pid;
    u32 started, status, killed, killed_at, reaped, done;
};

static int sd_start_ok(const struct sd_start_command *command) {
    return command->pid > 0 && command->done && command->reaped &&
        !command->killed && !command->status;
}

static void sd_start_poll(struct observer *o, struct sd_start_command *command) {
    if (command->done) return;
    u32 elapsed = now() - command->started;
    s32 rc = command->pid > 0 ? call(114, (u32)command->pid, (u32)&command->status, 1, 0, 0, 0) : -1;
    if (command->pid > 0 && rc == command->pid) command->reaped = 1;
    else if (rc == 0 || rc == -4) {
        if (elapsed >= 1500 && !command->killed) {
            call(37, (u32)command->pid, 9, 0, 0, 0, 0);
            command->killed = 1;
            command->killed_at = now();
        }
        if (!command->killed || now() - command->killed_at < 300) return;
    }
    command->done = 1;
    u32 data[8] = {2, 1, (u32)command->pid, command->status,
                  command->killed, command->reaped, elapsed, 0};
    emit(o, 5, data);
}

