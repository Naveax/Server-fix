#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace guard {

struct MetricLabel {
  std::string key;
  std::string value;
};

class IMetricSink {
 public:
  virtual ~IMetricSink() = default;
  virtual void inc_counter(std::string_view name, uint64_t value = 1,
                           const std::vector<MetricLabel>& labels = {}) = 0;
  virtual void set_gauge(std::string_view name, double value,
                         const std::vector<MetricLabel>& labels = {}) = 0;
  virtual void observe_histogram(std::string_view name, double value,
                                 const std::vector<MetricLabel>& labels = {}) = 0;
};

class NoopMetricSink final : public IMetricSink {
 public:
  void inc_counter(std::string_view, uint64_t, const std::vector<MetricLabel>&) override {}
  void set_gauge(std::string_view, double, const std::vector<MetricLabel>&) override {}
  void observe_histogram(std::string_view, double, const std::vector<MetricLabel>&) override {}
};

} // namespace guard
