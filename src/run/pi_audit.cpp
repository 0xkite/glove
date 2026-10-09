#include "pi_audit.hpp"

#include <algorithm>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace glove::run::detail {
namespace {

class pi_audit_sink final : public audit::sink {
public:
    pi_audit_sink(std::size_t max_events, std::size_t max_bytes)
        : max_events_{max_events}, max_bytes_{max_bytes} {
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
                    return std::unexpected("Pi audit capacity reached");
                }
                charge += field->size();
            }
            if (events_.size() >= max_events_ || retained_bytes_ > max_bytes_ - charge) {
                return std::unexpected("Pi audit capacity reached");
            }
            events_.push_back(event);
            retained_bytes_ += charge;
            return {};
        } catch (const std::bad_alloc&) {
            // Admission diagnostics and copies are guarded equally. Failed
            // observations never consume authority or turn into success.
            return pi_audit_allocation_error();
        }
    }

private:
    std::mutex mutex_;
    std::vector<audit::event> events_;
    std::size_t max_events_;
    std::size_t max_bytes_;
    std::size_t retained_bytes_ = 0;
};

} // namespace

auto make_pi_audit_sink(std::size_t max_events, std::size_t max_bytes)
    -> std::expected<std::shared_ptr<audit::sink>, std::string> {
    try {
        if (max_events == 0 || max_events > pi_audit_max_events ||
            max_bytes < sizeof(audit::event) || max_bytes > pi_audit_max_bytes) {
            return std::unexpected("invalid Pi audit bounds");
        }
        return std::make_shared<pi_audit_sink>(max_events, max_bytes);
    } catch (const std::bad_alloc&) {
        return pi_audit_allocation_error();
    }
}

} // namespace glove::run::detail
