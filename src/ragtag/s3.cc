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

#include "src/core/libcc/libcc.hh"
#include "src/core/libnet/s3.hh"

namespace RG {

int Main(int argc, char **argv)
{
    s3_Config config;
    s3_Session s3;

    if (!s3_DecodeURL("https://s3.us-west-004.backblazeb2.com/kippit/", &config))
        return 1;
    if (!s3.Open(config))
        return 1;

    if (argc >= 2) {
        Span<const char> payload = argv[1];
        const char *mimetype = (argc >= 3) ? argv[2] : nullptr;

        for (int i = 0; i < 1500; i++) {
            char key[32];
            Fmt(key, "prefixed/%1", FmtArg(i).Pad0(-5));

            if (!s3.PutObject(key, payload.As<const uint8_t>(), mimetype))
                return 1;
        }

        LogInfo("Uploaded!");
    } else {
        BlockAllocator temp_alloc;

        HeapArray<const char *> keys;
        if (!s3.ListObjects(nullptr, &temp_alloc, &keys))
            return 1;

        for (const char *key: keys) {
            LogInfo("KEY = %1", key);
        }

        LogInfo("Listed!");
    }

    return 0;
}

}

// C++ namespaces are stupid
int main(int argc, char **argv) { return RG::Main(argc, argv); }
