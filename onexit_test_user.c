#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "onexit_test_bpf.skel.h"

struct message {
  __u32 pid;
  __u32 tgid;
  __u64 timestamp_ns;
};

static volatile bool active = true;

static void handle_exit(int sig) {
  active = false;
}

// this func is called every time bpf gives us a new event
void handle_perf_sample(void* ctx, int cpu, void* data, __u32 data_sz) {
  struct message* msg = data;

  // check for bad data
  if (data_sz < sizeof(*msg)) {
    fprintf(stderr,
            "Bad data size: received %uB, expected %zuB\n",
            data_sz,
            sizeof(*msg));
    return;
  }

  printf("Event: pid = %u, tgid = %u, timestamp_ns = %llu\n", msg->pid, msg->tgid, msg->timestamp_ns);

  return;
}

// this func is called every time the buffer overflows
void handle_perf_lost(void* ctx, int cpu, __u64 lost_cnt) {
  fprintf(stderr, "Buffer overflow on CPU %d: lost %llu events", cpu, lost_cnt);
}

int main() {
  struct onexit_test_bpf* skel = NULL;
  struct perf_buffer* pb = NULL;
  int err;

  // attach signal handlers
  printf("Attaching signal handlers\n");
  signal(SIGINT, handle_exit);
  signal(SIGTERM, handle_exit);

  // load bpf program
  printf("Opening and loading BPF skeleton\n");
  skel = onexit_test_bpf__open_and_load();
  if (!skel) {
    perror("Failed to open and load BPF skeleton");
    return EXIT_FAILURE;
  }

  // attach bpf program to hook (see the bpf program src)
  printf("Attaching BPF program to hook\n");
  err = onexit_test_bpf__attach(skel);
  if (err) {
    perror("Failed to attach BPF program");
    goto cleanup;
  }

  // create perf buffer
  printf("Creating perf buffer\n");
  pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                        4,
                        handle_perf_sample,
                        NULL,
                        handle_perf_lost,
                        NULL);
  if (!pb) {
    fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(-err));
    goto cleanup;
  }

  printf("Starting to poll\n");
  while (active) {
    // block for time in ms
    err = perf_buffer__poll(pb, 100);

    if (err == -EINTR) {
      // interrupted by signal
      err = 0;
      break;
    }

    if (err < 0) {
      fprintf(stderr, "Failed to poll perf buffer: %s\n", strerror(-err));
      break;
    }
  }

cleanup:
  printf("Cleaning up\n");

  perf_buffer__free(pb);
  onexit_test_bpf__destroy(skel);

  if (err == 0) {
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
