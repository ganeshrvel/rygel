// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

#include "../../core/libcc/libcc.hh"
#include "vm.hh"
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "../../../vendor/miniz/miniz.h"

namespace RG {

static std::shared_mutex fs_mutex;
static HashMap<const char *, Span<const uint8_t>> fs_map;
static BlockAllocator fs_alloc;

static bool LoadViewFile(const char *zip_filename, const char *filename, Size max_len, Span<const uint8_t> *out_buf)
{
    mz_zip_archive zip;
    mz_zip_zero_struct(&zip);
    if (!mz_zip_reader_init_file(&zip, zip_filename, 0)) {
        LogError("Failed to open ZIP archive '%1': %2", zip_filename, mz_zip_get_error_string(zip.m_last_error));
        return false;
    }

    int idx = mz_zip_reader_locate_file(&zip, filename, nullptr, MZ_ZIP_FLAG_CASE_SENSITIVE);

    if (idx >= 0) {
        mz_zip_archive_file_stat sb;
        if (!mz_zip_reader_file_stat(&zip, (mz_uint)idx, &sb)) {
            LogError("Failed to stat '%1' in ZIP archive '%2': %3", filename, zip_filename, mz_zip_get_error_string(zip.m_last_error));
            return false;
        }

        if (max_len >= 0 && sb.m_uncomp_size > (mz_uint64)max_len) {
            LogError("File '%1' is too big to handle (max = %2)", filename, FmtDiskSize(max_len));
            return false;
        }

        Span<uint8_t> buf;
        {
            std::lock_guard<std::shared_mutex> lock(fs_mutex);

            buf.ptr = (uint8_t *)Allocator::Allocate(&fs_alloc, (Size)sb.m_uncomp_size);
            buf.len = (Size)sb.m_uncomp_size;
        }

        if (!mz_zip_reader_extract_to_mem(&zip, (mz_uint)idx, buf.ptr, (size_t)buf.len, 0)) {
            LogError("Failed to extract '%1' from ZIP archive '%2': %3", filename, zip_filename, mz_zip_get_error_string(zip.m_last_error));
            return false;
        }

        std::lock_guard<std::shared_mutex> lock(fs_mutex);
        fs_map.Set(filename, buf);

        *out_buf = buf;
        return true;
    } else {
        std::lock_guard<std::shared_mutex> lock(fs_mutex);
        fs_map.Set(filename, {});

        *out_buf = {};
        return true;
    }
}

int RunVM(Span<const char *> arguments)
{
    const auto print_usage = [=](FILE *fp) {
        PrintLn(fp, R"(Usage: %!..+%1 vm [options] <view_file>%!0)", FelixTarget);
    };

    // Parse arguments
    {
        OptionParser opt(arguments);

        while (opt.Next()) {
            if (opt.Test("--help")) {
                print_usage(stdout);
                return 0;
            } else {
                opt.LogUnknownError();
                return 1;
            }
        }
    }

    return 0;
}

}
