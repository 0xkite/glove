#pragma once

#include <cstdint>
#include <string>

namespace glove::container::linux_detail {

// One descriptor-pinned connected stream installed into a managed child.
// `descriptor_fd` is parent-owned until clone; `child_fd` is the committed exec number.
struct inherited_stream_descriptor {
    std::string alias;
    int descriptor_fd = -1;
    int child_fd = -1;
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t uid = 0;
    std::uint32_t mode = 0;
    std::uint64_t links = 0;
    std::uint64_t peer_device = 0;
    std::uint64_t peer_inode = 0;
    std::uint32_t peer_uid = 0;
    std::uint32_t peer_mode = 0;
    std::uint64_t peer_links = 0;
    std::string manifest_digest;
};

} // namespace glove::container::linux_detail
