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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#include "src/core/libcc/libcc.hh"
#include "chunker.hh"
#include "disk.hh"
#include "repository.hh"
#include "vendor/blake3/c/blake3.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace RG {

static const Size ChunkAverage = Kibibytes(1024);
static const Size ChunkMin = Kibibytes(512);
static const Size ChunkMax = Kibibytes(2048);

bool kt_ExtractFile(kt_Disk *disk, const kt_ID &id, const char *dest_filename, Size *out_len)
{
    // Open destination file
    StreamWriter writer(dest_filename);
    if (!writer.IsValid())
        return false;

    // Read file summary
    HeapArray<uint8_t> summary;
    {
        if (!disk->Read(id, &summary))
            return false;
        if (summary.len % RG_SIZE(kt_ID)) {
            LogError("Malformed file summary '%1'", id);
            return false;
        }
    }

    // Write unencrypted file
    for (Size idx = 0, offset = 0; offset < summary.len; idx++, offset += RG_SIZE(kt_ID)) {
        kt_ID id = {};
        memcpy(&id, summary.ptr + offset, RG_SIZE(id));

        HeapArray<uint8_t> buf;
        if (!disk->Read(id, &buf))
            return false;
        if (!writer.Write(buf))
            return false;
    }

    if (!writer.Close())
        return false;

    if (out_len) {
        *out_len = writer.GetRawWritten();
    }
    return true;
}

bool kt_BackupFile(kt_Disk *disk, const char *src_filename, kt_ID *out_id, Size *out_written)
{
    Span<const uint8_t> salt = disk->GetSalt();
    RG_ASSERT(salt.len == BLAKE3_KEY_LEN); // 32 bytes

    // Open file
    int fd = OpenDescriptor(src_filename, (int)OpenFlag::Read);
    if (fd < 0)
        return false;
    RG_DEFER { close(fd); };

    // Map file in memory
    Span<const uint8_t> file;
    {
        struct stat sb;
        if (fstat(fd, &sb) < 0) {
            LogError("Failed to stat file '%1': %2", src_filename, strerror(errno));
            return false;
        }

        file.ptr = (const uint8_t *)mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        file.len = (Size)sb.st_size;

        if (!file.ptr) {
            LogError("Failed to mmap file '%1': %2", src_filename, strerror(errno));
            return false;
        }
    }
    RG_DEFER { munmap((void *)file.ptr, file.len); };

    // Split the file
    kt_ID file_id = {};
    HeapArray<uint8_t> summary;
    std::atomic<Size> written = 0;
    {
        Span<const uint8_t> remain = file;
        kt_Chunker chunker(ChunkAverage, ChunkMin, ChunkMax);

        summary.Reserve((file.len / ChunkMin + 1) * RG_SIZE(kt_ID));

        Async async;

        async.Run([&]() {
            blake3_hasher hasher;
            blake3_hasher_init_keyed(&hasher, salt.ptr);
            blake3_hasher_update(&hasher, file.ptr, (size_t)file.len);
            blake3_hasher_finalize(&hasher, file_id.hash, RG_SIZE(file_id.hash));

            return true;
        });

        while (remain.len) {
            Size processed = chunker.Process(remain, true, [&](Size idx, Size total, Span<const uint8_t> chunk) {
                RG_ASSERT(idx * 32 == summary.len);
                summary.len += 32;

                async.Run([=, &written]() {
                    kt_ID id = {};
                    {
                        blake3_hasher hasher;
                        blake3_hasher_init_keyed(&hasher, salt.ptr);
                        blake3_hasher_update(&hasher, chunk.ptr, chunk.len);
                        blake3_hasher_finalize(&hasher, id.hash, RG_SIZE(id.hash));
                    }

                    Size ret = disk->Write(id, chunk);
                    if (ret < 0)
                        return false;
                    written += ret;

                    memcpy(summary.ptr + idx * RG_SIZE(id), &id, RG_SIZE(id));

                    return true;
                });

                return true;
            });

            // The callback never fails
            RG_ASSERT(processed >= 0);

            remain.ptr += processed;
            remain.len -= processed;
        }

        if (!async.Sync())
            return false;
    }

    // Write list of chunks
    {
        Size ret = disk->Write(file_id, summary);
        if (ret < 0)
            return false;
        written += ret;
    }

    *out_id = file_id;
    if (out_written) {
        *out_written = written;
    }
    return true;
}

}
