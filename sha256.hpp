#pragma once

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

class SHA256
{
private:

    std::array<uint32_t, 8> state{
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u
    };

    static constexpr uint32_t K[64] =
    {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    static uint32_t rotateRight(uint32_t value, uint32_t amount)
    {
        return (value >> amount) | (value << (32 - amount));
    }

    void transform(const uint8_t* data)
    {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i)
        {
            w[i] =
                (static_cast<uint32_t>(data[i * 4]) << 24) |
                (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(data[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i)
        {
            uint32_t s0 =
                rotateRight(w[i - 15], 7) ^
                rotateRight(w[i - 15], 18) ^
                (w[i - 15] >> 3);

            uint32_t s1 =
                rotateRight(w[i - 2], 17) ^
                rotateRight(w[i - 2], 19) ^
                (w[i - 2] >> 10);

            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (int i = 0; i < 64; ++i)
        {
            uint32_t s1 =
                rotateRight(e, 6) ^
                rotateRight(e, 11) ^
                rotateRight(e, 25);

            uint32_t choose = (e & f) ^ (~e & g);

            uint32_t temp1 =
                h + s1 + choose + K[i] + w[i];

            uint32_t s0 =
                rotateRight(a, 2) ^
                rotateRight(a, 13) ^
                rotateRight(a, 22);

            uint32_t majority =
                (a & b) ^ (a & c) ^ (b & c);

            uint32_t temp2 = s0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

public:

    static std::string hash(const std::string& input)
    {
        SHA256 context;

        std::vector<uint8_t> data(
            input.begin(),
            input.end()
        );

        uint64_t bitLength =
            static_cast<uint64_t>(data.size()) * 8;

        data.push_back(0x80);

        while (data.size() % 64 != 56)
        {
            data.push_back(0x00);
        }

        for (int i = 7; i >= 0; --i)
        {
            data.push_back(
                static_cast<uint8_t>(
                    (bitLength >> (i * 8)) & 0xff
                )
            );
        }

        for (size_t i = 0; i < data.size(); i += 64)
        {
            context.transform(data.data() + i);
        }

        std::ostringstream output;

        output << std::hex << std::setfill('0');

        for (uint32_t value : context.state)
        {
            output << std::setw(8) << value;
        }

        return output.str();
    }
};

constexpr uint32_t SHA256::K[64];