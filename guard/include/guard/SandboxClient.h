#pragma once
#include "Common.h"
#include "Metrics.h"
#include <cstdint>
#include <string>

namespace guard {

enum class SandboxStatus : uint8_t { Ok = 0, Invalid = 1, Timeout = 2, WouldBlock = 3, Crash = 4 };

struct SandboxConfig {
  uint32_t timeout_ms{2};
  uint32_t max_inflight{8};
  std::string worker_path{"./sandbox_worker"};
  bool inprocess_fallback{false};
};

class SandboxClient {
 public:
  explicit SandboxClient(const SandboxConfig& cfg, IMetricSink* metrics = nullptr);
  ~SandboxClient();
  SandboxStatus decode_packet(const PacketView& pkt);

 private:
  SandboxConfig cfg_{};
  IMetricSink* metrics_{nullptr};
  uint32_t inflight_{0};

  // POSIX process handles
  int child_pid_{-1};
  int fd_write_{-1};
  int fd_read_{-1};

  bool ensure_worker();
  void shutdown_worker();
};

} // namespace guard
