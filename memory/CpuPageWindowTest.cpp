#include "CpuPageWindow.h"

#include <array>
#include <cstdio>

using local_xmem::CpuPageWindow;
constexpr size_t size = CpuPageWindow::page_size;
constexpr auto none = CpuPageWindow::unmapped;

static bool state(void* address, DWORD expected) {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(address, &info, sizeof info) == sizeof info && info.State == expected;
}

// Stop before dereferencing a view if an earlier mapping failed.
#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "line %d failed: %s (last error %lu)\n", __LINE__, #expression, GetLastError()); \
    return 1; } } while (false)

int main() {
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 3 * size, nullptr);
    CHECK(section != nullptr);
    auto source = CpuPageWindow::reserve(section, 3);
    auto dest = CpuPageWindow::reserve(section, 4);
    CHECK(CloseHandle(section));
    CHECK(source && dest);
    auto* a = static_cast<unsigned char*>(source->base());
    auto* b = static_cast<unsigned char*>(dest->base());
    CHECK(state(b, MEM_RESERVE) && state(b + 3 * size, MEM_RESERVE));

    CHECK(source->map_range(0, std::array<uint64_t, 3>{0, 1, 2}) == ERROR_SUCCESS);
    for (size_t p = 0; p < 3; ++p) {
        a[p * size] = static_cast<unsigned char>(10 + p);
        a[(p + 1) * size - 1] = static_cast<unsigned char>(20 + p);
    }
    CHECK(dest->map_scatter(std::array<size_t, 3>{3, 0, 2}, std::array<uint64_t, 3>{0, 2, 0}) == ERROR_SUCCESS);
    CHECK(b[0] == 12 && b[size - 1] == 22 && b[4 * size - 1] == 20);
    b[2 * size + 37] = 91;
    CHECK(a[37] == 91 && b[3 * size + 37] == 91);

    CHECK(dest->map_range(2, std::array<uint64_t, 1>{1}) == ERROR_SUCCESS);
    CHECK(b[2 * size] == 11 && b[3 * size] == 10);
    CHECK(dest->map_scatter(std::array<size_t, 2>{0, 3}, std::array<uint64_t, 2>{none, none}) == ERROR_SUCCESS);
    CHECK(state(b, MEM_RESERVE) && state(b + 3 * size, MEM_RESERVE));
    CHECK(a[37] == 91 && b[2 * size] == 11);

    CHECK(dest->map_range(0, std::array<uint64_t, 2>{2, 1}) == ERROR_SUCCESS);
    // Page 3 lies beyond the three-page section. The first replacement succeeds,
    // the second fails inside Windows, and both old views must be restored.
    CHECK(dest->map_range(0, std::array<uint64_t, 2>{0, 3}) != ERROR_SUCCESS);
    CHECK(state(b, MEM_COMMIT) && state(b + size, MEM_COMMIT));
    CHECK(b[0] == 12 && b[size] == 11);
    b[size] = 47;
    CHECK(a[size] == 47);
    CHECK(dest->map_scatter(std::array<size_t, 2>{0, 0}, std::array<uint64_t, 2>{0, 1}) == ERROR_INVALID_PARAMETER);
    CHECK(dest->map_scatter(std::array<size_t, 1>{4}, std::array<uint64_t, 1>{0}) == ERROR_INVALID_PARAMETER);
    CHECK(dest->map_scatter(std::array<size_t, 1>{0}, {}) == ERROR_INVALID_PARAMETER);
    CHECK(dest->map_range(SIZE_MAX, std::array<uint64_t, 1>{0}) == ERROR_INVALID_PARAMETER);
    CHECK(dest->map_range(2, std::array<uint64_t, 1>{UINT64_MAX - 1}) == ERROR_INVALID_PARAMETER);
    CHECK(b[0] == 12 && b[size] == 47);

    source.reset();
    CHECK(state(a, MEM_FREE) && b[0] == 12 && b[size] == 47);
    dest.reset();
    CHECK(state(b, MEM_FREE) && state(b + 3 * size, MEM_FREE));
    std::puts("64 KiB CPU aliases: range, scatter, shared writes, remap, unmap, rollback and release passed.");
    return 0;
}
