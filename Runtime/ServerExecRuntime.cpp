#include <iostream>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <random>
#include <string>

#ifndef SERVEREXEC_HOST
#define SERVEREXEC_HOST "127.0.0.1"
#endif
#ifndef SERVEREXEC_PORT
#define SERVEREXEC_PORT "8080"
#endif

namespace net = boost::asio;
using tcp = net::ip::tcp;

#pragma pack(push, 1)
struct SvxRequest
{
    uint8_t sessionid[16];
    uint8_t siteid[16];
    int64_t a;
    int64_t b;
    uint8_t version;
};
struct SvxReply
{
    int64_t result;
    uint8_t status;
};
#pragma pack(pop)

static_assert(sizeof(SvxRequest) == 49, "SvxRequest must be 49 bytes on the wire");
static_assert(sizeof(SvxReply) == 9, "SvxReply must be 9 bytes on the wire");

static constexpr uint8_t SVXWireVersion = 2;
static constexpr uint8_t SVXStatusOk = 0;
static constexpr uint8_t SVXStatusUnknownSite = 1;
static constexpr uint8_t SVXStatusInternal = 2;
static constexpr uint8_t SVXStatusOrderViolation = 3;

static const std::array<uint8_t, 16>& SessionId()
{
    static const std::array<uint8_t, 16> id = []()
        {
            std::array<uint8_t, 16> out{};
            std::random_device rd;
            for (int i = 0; i < 16; i += 4)
            {
                uint32_t r = rd();
                std::memcpy(out.data() + i, &r, 4);
            }
            return out;
        }();
    return id;
}

static std::string Hex32(const uint8_t* id16)
{
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.resize(32);
    for (int i = 0; i < 16; ++i)
    {
        s[2 * i] = hex[(id16[i] >> 4) & 0xf];
        s[2 * i + 1] = hex[id16[i] & 0xf];
    }
    return s;
}

[[noreturn]] static void SVXAbort(const char* why, const char* site)
{
    std::fprintf(stderr, "[serverexec] fatal: %s (site=%s)\n", why, site);
    std::abort();
}

__attribute__((annotate("ServerExecCommunicator")))
int64_t ServerExecCommunicate(const uint8_t* site, int64_t a, int64_t b)
{
    try
    {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(SERVEREXEC_HOST, SERVEREXEC_PORT);

        tcp::socket sock(ioc);
        net::connect(sock, endpoints);

        boost::system::error_code ec;
        sock.set_option(tcp::no_delay(true), ec);

        SvxRequest req{};
        std::memcpy(req.sessionid, SessionId().data(), 16);
        std::memcpy(req.siteid, site, 16);
        req.a = a;
        req.b = b;
        req.version = SVXWireVersion;

        size_t n = net::write(sock, net::buffer(&req, sizeof(req)), ec);
        if (ec || n != sizeof(req)) SVXAbort("write failed", Hex32(site).c_str());

        SvxReply reply{};
        n = net::read(sock, net::buffer(&reply, sizeof(reply)), ec);
        if (ec || n != sizeof(reply)) SVXAbort("short/failed read", Hex32(site).c_str());

        sock.shutdown(tcp::socket::shutdown_both, ec);

        if (reply.status != SVXStatusOk)
        {
            const char* kind;
            switch (reply.status)
            {
            case SVXStatusUnknownSite: kind = "unknown site"; break;
            case SVXStatusInternal: kind = "server internal"; break;
            case SVXStatusOrderViolation: kind = "order violation"; break;
            default: kind = "unknown status"; break;
            }
            char buf[80];
            std::snprintf(buf, sizeof(buf), "server rejected: %s (status=%u)", kind, static_cast<unsigned>(reply.status));
            SVXAbort(buf, Hex32(site).c_str());
        }

        return reply.result;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[serverexec] exception: %s\n", e.what());
        SVXAbort("transport error", Hex32(site).c_str());
    }
}
