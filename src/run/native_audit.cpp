#include "native_audit.hpp"

#include <algorithm>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace {

class native_audit_sink final : public audit::sink {
public:
    native_audit_sink(std::size_t max_events, std::size_t max_bytes, std::string_view label)
        : max_events_{max_events},
          max_bytes_{max_bytes},
          capacity_error_{std::string{label} + " audit capacity reached"} {
        // No vector growth can exceed the admitted event-count storage. The
        // byte budget also charges each event's fixed storage, not just strings.
        events_.reserve(std::min(max_events_, max_bytes_ / sizeof(audit::event)));
    }

    auto record(const audit::event& event) -> std::expected<void, std::string> override {
        try {
            std::scoped_lock lock{mutex_};
            std::size_t charge = sizeof(audit::event);
            for (const auto* field :
                 {&event.tool_name, &event.arguments_json, &event.error_message}) {
                if (field->size() > max_bytes_ - charge) {
                    return std::unexpected(capacity_error_);
                }
                charge += field->size();
            }
            if (events_.size() >= max_events_ || retained_bytes_ > max_bytes_ - charge) {
                return std::unexpected(capacity_error_);
            }
            events_.push_back(event);
            retained_bytes_ += charge;
            return {};
        } catch (const std::bad_alloc&) {
            // Admission diagnostics and copies are guarded equally. Failed
            // observations never consume authority or turn into success.
            return native_audit_allocation_error();
        }
    }

private:
    std::mutex mutex_;
    std::vector<audit::event> events_;
    std::size_t max_events_;
    std::size_t max_bytes_;
    std::size_t retained_bytes_ = 0;
    std::string capacity_error_;
};

} // namespace

auto make_native_audit_sink(std::size_t max_events, std::size_t max_bytes, std::string_view label)
    -> std::expected<std::shared_ptr<audit::sink>, std::string> {
    try {
        if (label.empty() || label.size() > 64 || label.find('\0') != std::string_view::npos) {
            return std::unexpected("invalid native audit label");
        }
        if (max_events == 0 || max_events > native_audit_max_events ||
            max_bytes < sizeof(audit::event) || max_bytes > native_audit_max_bytes) {
            return std::unexpected("invalid " + std::string{label} + " audit bounds");
        }
        return std::make_shared<native_audit_sink>(max_events, max_bytes, label);
    } catch (const std::bad_alloc&) {
        return native_audit_allocation_error();
    }
}

} // namespace glove::run::detail
