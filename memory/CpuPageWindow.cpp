#include "CpuPageWindow.h"

#include <algorithm>
#include <new>

namespace local_xmem {

DWORD map_cpu_page(void* address, HANDLE section, uint64_t page) {
    constexpr size_t bytes = CpuPageWindow::page_size;
    if (page >= UINT64_MAX / bytes) return ERROR_INVALID_PARAMETER;
    return MapViewOfFile3(section, GetCurrentProcess(), address, page * bytes, bytes,
                          MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0) ? ERROR_SUCCESS : GetLastError();
}

DWORD unmap_cpu_page(void* address) {
    return UnmapViewOfFile2(GetCurrentProcess(), address, MEM_PRESERVE_PLACEHOLDER) ? ERROR_SUCCESS : GetLastError();
}

CpuPageWindow::CpuPageWindow(size_t slots) : current_(slots, unmapped) {}

std::unique_ptr<CpuPageWindow> CpuPageWindow::reserve(HANDLE section, size_t slots) {
    if (!slots || slots > SIZE_MAX / page_size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return {};
    }
    std::unique_ptr<CpuPageWindow> result;
    try {
        result.reset(new CpuPageWindow(slots));
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return {};
    }
    HANDLE self = GetCurrentProcess();
    if (!DuplicateHandle(self, section, self, &result->section_, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return {};
    }
    result->base_ = static_cast<unsigned char*>(VirtualAlloc2(self, nullptr, slots * page_size,
        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0));
    if (!result->base_) return {};
    // MapViewOfFile3 requires an exact placeholder for each view. During an
    // interrupted split, the suffix is still one reservation owned by this window.
    while (result->splits_ + 1 < slots) {
        auto* next = result->base_ + result->splits_ * page_size;
        if (!VirtualFree(next, page_size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) return {};
        ++result->splits_;
    }
    return result;
}

CpuPageWindow::~CpuPageWindow() {
    const DWORD saved = GetLastError();
    if (base_) {
        for (size_t i = 0; i <= splits_; ++i) {
            void* address = base_ + i * page_size;
            if (current_[i] == unmapped) VirtualFree(address, 0, MEM_RELEASE);
            else UnmapViewOfFile(address);
        }
    }
    if (section_) CloseHandle(section_);
    SetLastError(saved);
}

DWORD CpuPageWindow::replace(size_t slot, uint64_t page) {
    if (current_[slot] == page) return ERROR_SUCCESS;
    void* address = base_ + slot * page_size;
    if (current_[slot] != unmapped) {
        const DWORD error = unmap_cpu_page(address);
        if (error) return error;
        current_[slot] = unmapped;
    }
    if (page != unmapped) {
        const DWORD error = map_cpu_page(address, section_, page);
        if (error) return error;
        current_[slot] = page;
    }
    return ERROR_SUCCESS;
}

DWORD CpuPageWindow::map_range(size_t first, std::span<const uint64_t> pages) {
    if (first > current_.size() || pages.size() > current_.size() - first) return ERROR_INVALID_PARAMETER;
    return update(first, {}, pages);
}

DWORD CpuPageWindow::map_scatter(std::span<const size_t> slots, std::span<const uint64_t> pages) {
    if (slots.size() != pages.size()) return ERROR_INVALID_PARAMETER;
    return update(0, slots, pages);
}

DWORD CpuPageWindow::update(size_t first, std::span<const size_t> slots, std::span<const uint64_t> pages) {
    struct Change { size_t slot; uint64_t next; uint64_t previous; };
    const std::lock_guard guard(lock_);
    if (!healthy_) return ERROR_INVALID_STATE;
    if (pages.size() > current_.size()) return ERROR_INVALID_PARAMETER;
    std::vector<Change> changes;
    try {
        changes.reserve(pages.size());
        for (size_t i = 0; i < pages.size(); ++i) {
            const size_t slot = slots.empty() ? first + i : slots[i];
            const uint64_t page = pages[i];
            if (slot >= current_.size() || (page != unmapped && page >= UINT64_MAX / page_size)) {
                return ERROR_INVALID_PARAMETER;
            }
            changes.push_back({slot, page, current_[slot]});
        }
    } catch (const std::bad_alloc&) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!slots.empty()) {
        std::sort(changes.begin(), changes.end(), [](auto& a, auto& b) { return a.slot < b.slot; });
        for (size_t i = 1; i < changes.size(); ++i) {
            if (changes[i].slot == changes[i - 1].slot) return ERROR_INVALID_PARAMETER;
        }
    }
    for (size_t i = 0; i < changes.size(); ++i) {
        const DWORD error = replace(changes[i].slot, changes[i].next);
        if (error != ERROR_SUCCESS) {
            // The failing replacement may already have unmapped its old view.
            for (size_t j = i + 1; j > 0; --j) {
                const auto& change = changes[j - 1];
                if (replace(change.slot, change.previous) != ERROR_SUCCESS) healthy_ = false;
            }
            return healthy_ ? error : ERROR_INVALID_STATE;
        }
    }
    return ERROR_SUCCESS;
}
}
