#pragma once

#include <windows.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace local_xmem {

DWORD map_cpu_page(void* address, HANDLE section, uint64_t page);
DWORD unmap_cpu_page(void* address);

// A CPU-only window into a pagefile-backed section. Different windows can share
// the same section. Page indices are host-side offsets, never Xbox page tokens.
class CpuPageWindow {
public:
    static constexpr size_t page_size = 64 * 1024;
    static constexpr uint64_t unmapped = UINT64_MAX;

    static std::unique_ptr<CpuPageWindow> reserve(HANDLE section, size_t slots);
    ~CpuPageWindow();
    CpuPageWindow(const CpuPageWindow&) = delete;
    CpuPageWindow& operator=(const CpuPageWindow&) = delete;

    void* base() const { return base_; }
    // Supply unmapped as a page index to restore a slot to a reserved placeholder.
    DWORD map_range(size_t first_slot, std::span<const uint64_t> pages);
    DWORD map_scatter(std::span<const size_t> slots, std::span<const uint64_t> pages);

private:
    explicit CpuPageWindow(size_t slots);
    DWORD update(size_t first, std::span<const size_t> slots, std::span<const uint64_t> pages);
    DWORD replace(size_t slot, uint64_t page);

    HANDLE section_ = nullptr;
    unsigned char* base_ = nullptr;
    std::vector<uint64_t> current_;
    size_t splits_ = 0;
    std::mutex lock_;
    bool healthy_ = true;
};
}
