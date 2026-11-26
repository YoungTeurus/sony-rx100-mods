#define SD_INPUT_LIMIT 1024u
#if M7_RAM_PRECAPTURE
#define SD_INPUT_CHANGE_LIMIT 2048u
#else
#define SD_INPUT_CHANGE_LIMIT 200u
#endif
#define SD_INPUT_UNKNOWN 0x7fffffffu

struct sd_input_entry {
    u32 key, status, config_index;
    u32 config_key, local_code, remap, config_flags;
    unsigned char valid, announced, pending;
};

struct sd_input {
    u32 failed, initialized;
    u32 root, config, state, count;
    u32 last_ms, changes;
    struct sd_input_entry entries[SD_INPUT_LIMIT];
    u32 snapshot[SD_INPUT_LIMIT * 10];
};

struct sd_input_shape {
    u32 root, config, state, count;
};

static int sd_input_overlap(u32 first, u32 first_size, u32 second, u32 second_size) {
    return first < second + second_size && second < first + first_size;
}

static int sd_input_private(struct observer *o, u32 address, u32 size) {
    if ((address & 3) || address < 0x10000 || address >= 0xc0000000 ||
        !size || size > 0xc0000000 - address) return 0;
    /* P, C and S cannot alias the pinned libObj mappings, including anonymous BSS. */
    if (sd_input_overlap(address, size, m7_config.bias, 0x1464000)) return 0;
    return private_range(o, address, size);
}

static int sd_input_read_shape(struct observer *o, struct sd_input_shape *shape) {
    u32 words[10];
    if (m7_config.bias < 0x10000 || m7_config.bias > 0xc0000000 - 0x1464000 ||
        !read_mem(o, m7_config.bias + 0x145d230, &shape->root, 4) ||
        !sd_input_private(o, shape->root, 0x224) ||
        !read_mem(o, shape->root, words, sizeof(words))) return 0;
    shape->config = words[6];
    shape->count = words[7];
    shape->state = words[9];
    if (words[0] != m7_config.bias + 0x1387af0 || !shape->count ||
        shape->count > SD_INPUT_LIMIT ||
        !sd_input_private(o, shape->config, shape->count * 0x30) ||
        !sd_input_private(o, shape->state, shape->count * 0x28)) return 0;
    return !sd_input_overlap(shape->root, 0x224, shape->config, shape->count * 0x30) &&
        !sd_input_overlap(shape->root, 0x224, shape->state, shape->count * 0x28) &&
        !sd_input_overlap(shape->config, shape->count * 0x30,
                          shape->state, shape->count * 0x28);
}

static int sd_input_same_shape(const struct sd_input *input,
                               const struct sd_input_shape *shape) {
    return input->root == shape->root && input->config == shape->config &&
        input->state == shape->state && input->count == shape->count;
}

static int sd_input_candidate(u32 key) {
    return key == 0xa7 || key == 0x1f1 || key == 0x1f4 || key == 0x1a00000d || key == 0x1a00000e;
}

static void sd_input_config_event(struct observer *o, struct sd_input *input, u32 index) {
    struct sd_input_entry *entry = &input->entries[index];
    u32 data[8] = {index, entry->config_key, index, entry->local_code,
                   entry->remap, entry->config_flags, 0, 0};
    emit(o, 77, data);
    entry->announced = 1;
}

static int sd_input_init(struct observer *o, struct sd_input *input) {
    struct sd_input_shape shape = {0};
    u32 data[8] = {0};
    __aeabi_memclr8(input, sizeof(*input));
    input->last_ms = now();
    if (!sd_input_read_shape(o, &shape)) goto failed;
    input->root = shape.root;
    input->config = shape.config;
    input->state = shape.state;
    input->count = shape.count;
    for (u32 base = 0; base < input->count; base += 64) {
        u32 count = input->count - base;
        if (count > 64) count = 64;
        if (!read_mem(o, input->config + base * 0x30, input->snapshot, count * 0x30))
            goto failed;
        for (u32 i = 0; i < count; ++i) {
            struct sd_input_entry *entry = &input->entries[base + i];
            const u32 *config = &input->snapshot[i * 12];
            entry->config_key = config[2];
            entry->local_code = config[3];
            entry->remap = config[7];
            entry->config_flags = config[8];
        }
    }
    if (!read_mem(o, input->state, input->snapshot, input->count * 0x28) ||
        !sd_input_read_shape(o, &shape) || !sd_input_same_shape(input, &shape)) goto failed;
    for (u32 i = 0; i < input->count; ++i) {
        struct sd_input_entry *entry = &input->entries[i];
        const u32 *state = &input->snapshot[i * 10];
        entry->key = state[0];
        entry->status = state[2];
        entry->config_index = state[4];
        entry->valid = state[0] == entry->config_key && state[4] == i;
    }
    input->initialized = 1;
    data[0] = 1;
    data[1] = input->root;
    data[2] = input->config;
    data[3] = input->state;
    data[4] = input->count;
    emit(o, 76, data);
    for (u32 i = 0; i < input->count; ++i)
        if (sd_input_candidate(input->entries[i].config_key)) sd_input_config_event(o, input, i);
    return 1;

failed:
    input->failed = 1;
    data[1] = shape.root;
    data[2] = shape.config;
    data[3] = shape.state;
    data[4] = shape.count;
    emit(o, 76, data);
    return 0;
}

static void sd_input_sample(struct observer *o, struct sd_input *input) {
    struct sd_input_shape shape = {0};
    u32 timestamp, verify[12];
    if (input->failed || !input->initialized) return;
    timestamp = now();
    if ((u32)(timestamp - input->last_ms) < 20) return;
    input->last_ms = timestamp;
    if (!sd_input_read_shape(o, &shape) || !sd_input_same_shape(input, &shape) ||
        !read_mem(o, input->state, input->snapshot, input->count * 0x28)) goto failed;
    for (u32 i = 0; i < input->count; ++i) {
        struct sd_input_entry *entry = &input->entries[i];
        const u32 *state = &input->snapshot[i * 10];
        entry->pending = 0;
        if (entry->key == state[0] && entry->status == state[2] &&
            entry->config_index == state[4]) continue;
        if (!read_mem(o, input->state + i * 0x28, verify, 20)) goto failed;
        /* Discard an inconsistent row; matching reads do not imply an atomic snapshot. */
        if (verify[0] != state[0] || verify[1] != state[1] ||
            verify[2] != state[2] || verify[4] != state[4]) continue;
        if (state[0] != entry->config_key || state[4] != i) {
            if (entry->valid) goto failed;
            entry->pending = 2;
            continue;
        }
        if (!read_mem(o, input->config + i * 0x30, verify, sizeof(verify)) ||
            verify[2] != entry->config_key || verify[3] != entry->local_code ||
            verify[7] != entry->remap || verify[8] != entry->config_flags) goto failed;
        entry->pending = 1;
    }
    if (!sd_input_read_shape(o, &shape) || !sd_input_same_shape(input, &shape)) goto failed;
    for (u32 i = 0; i < input->count; ++i) {
        struct sd_input_entry *entry = &input->entries[i];
        const u32 *state = &input->snapshot[i * 10];
        if (!entry->pending) continue;
        if (entry->pending == 1) {
            u32 data[8] = {i, state[0], entry->valid ? entry->status : SD_INPUT_UNKNOWN,
                           state[2], state[4], state[1], 0, 0};
            if (input->changes == SD_INPUT_CHANGE_LIMIT) goto failed;
            if (!entry->announced) sd_input_config_event(o, input, i);
            emit(o, 78, data);
            ++input->changes;
            entry->valid = 1;
        }
        entry->key = state[0];
        entry->status = state[2];
        entry->config_index = state[4];
        entry->pending = 0;
    }
    return;

failed:
    input->failed = 1;
}
