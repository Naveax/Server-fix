#include "guard/SandboxClient.h"
#include "guard/Parser.h"
#include <cstring>

#ifdef _WIN32
// In-process fallback on Windows for reference implementation.
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#endif

namespace guard {

SandboxClient::SandboxClient(const SandboxConfig& cfg, IMetricSink* metrics)
    : cfg_(cfg), metrics_(metrics) {}

SandboxClient::~SandboxClient() { shutdown_worker(); }

bool SandboxClient::ensure_worker() {
#ifdef _WIN32
  return false;
#else
  if (child_pid_ > 0) return true;
  int in_pipe[2];
  int out_pipe[2];
  if (pipe(in_pipe) != 0) return false;
  if (pipe(out_pipe) != 0) return false;

  pid_t pid = fork();
  if (pid == 0) {
    // child
    dup2(in_pipe[0], STDIN_FILENO);
    dup2(out_pipe[1], STDOUT_FILENO);
    close(in_pipe[1]);
    close(out_pipe[0]);
    execl(cfg_.worker_path.c_str(), cfg_.worker_path.c_str(), (char*)nullptr);
    _exit(1);
  }
  if (pid < 0) return false;

  child_pid_ = pid;
  fd_write_ = in_pipe[1];
  fd_read_ = out_pipe[0];
  close(in_pipe[0]);
  close(out_pipe[1]);

  fcntl(fd_read_, F_SETFL, O_NONBLOCK);
  return true;
#endif
}

void SandboxClient::shutdown_worker() {
#ifdef _WIN32
  return;
#else
  if (child_pid_ > 0) {
    close(fd_write_);
    close(fd_read_);
    int status = 0;
    waitpid(child_pid_, &status, 0);
  }
  child_pid_ = -1;
  fd_write_ = -1;
  fd_read_ = -1;
#endif
}

SandboxStatus SandboxClient::decode_packet(const PacketView& pkt) {
#ifdef _WIN32
  if (cfg_.inprocess_fallback) {
    ParserBudgetConfig bc{};
    auto res = parse_example_frame(pkt, bc);
    return res.ok ? SandboxStatus::Ok : SandboxStatus::Invalid;
  }
  return SandboxStatus::Ok;
#else
  if (cfg_.inprocess_fallback) {
    ParserBudgetConfig bc{};
    auto res = parse_example_frame(pkt, bc);
    return res.ok ? SandboxStatus::Ok : SandboxStatus::Invalid;
  }

  if (inflight_ >= cfg_.max_inflight) return SandboxStatus::WouldBlock;
  if (!ensure_worker()) return SandboxStatus::Crash;

  uint16_t len = static_cast<uint16_t>(pkt.len > 0xFFFF ? 0xFFFF : pkt.len);
  uint8_t hdr[2] = {static_cast<uint8_t>((len >> 8) & 0xFF), static_cast<uint8_t>(len & 0xFF)};

  if (write(fd_write_, hdr, 2) != 2) return SandboxStatus::Crash;
  if (write(fd_write_, pkt.data, len) != len) return SandboxStatus::Crash;

  inflight_++;

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd_read_, &rfds);
  struct timeval tv;
  tv.tv_sec = cfg_.timeout_ms / 1000;
  tv.tv_usec = (cfg_.timeout_ms % 1000) * 1000;

  int r = select(fd_read_ + 1, &rfds, nullptr, nullptr, &tv);
  if (r <= 0) {
    inflight_--;
    if (metrics_) metrics_->inc_counter("guard_sandbox_timeout_total", 1);
    return SandboxStatus::Timeout;
  }
  uint8_t resp = 0;
  if (read(fd_read_, &resp, 1) != 1) {
    inflight_--;
    if (metrics_) metrics_->inc_counter("guard_sandbox_crash_total", 1);
    return SandboxStatus::Crash;
  }

  inflight_--;
  return resp == 0 ? SandboxStatus::Ok : SandboxStatus::Invalid;
#endif
}

} // namespace guard
