#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace net = boost::asio;
namespace fs = std::filesystem;
using tcp = net::ip::tcp;

// reordering or resizing any field in SvxRequest / SvxReply or dropping #pragma pack(push,1) silently breaks wire compat with ServerExecRuntime.cpp
// both files MUST change in lockstep; the static_asserts on sizeof enforce it at build time
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

static constexpr const char* DefaultBind = "127.0.0.1";
static constexpr unsigned short DefaultPort = 8080;
// This filename MUST match ServerExecPass.cpp's ManifestPath; the pass writes it at compile time, the server reads it at startup, and a lockstep rename across both files is the ONLY way to change it without breaking first-run on the default path
static constexpr const char* DefaultManifest = "SvxManifest.json";

enum class SVXOp : uint8_t
{
    Unknown = 0,
    Add,
    Sub,
    Xor,
    Mul,
    And,
    Or,
    Shl,
    LShr,
    AShr,
    UDiv,
    SDiv,
    URem,
    SRem,
};

static constexpr uint64_t FNV1a64(const char* s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    while (*s)
    {
        h ^= (uint8_t)(*s);
        h *= 0x100000001b3ULL;
        ++s;
    }
    return h;
}

static uint64_t FNV1a64Range(std::string_view s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (char c : s)
    {
        h ^= (uint8_t)c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

// FNV1a64 case constants and FNV1a64Range at runtime MUST agree byte for byte on offset basis / prime / iteration / casing; the lowercase here matches the pass's OpcodeName output which the manifest writes verbatim; any case mismatch silently drops every site to SVXOp::Unknown
static SVXOp ParseOp(const std::string& s)
{
    switch (FNV1a64Range(s))
    {
    case FNV1a64("add"): return SVXOp::Add;
    case FNV1a64("sub"): return SVXOp::Sub;
    case FNV1a64("xor"): return SVXOp::Xor;
    case FNV1a64("mul"): return SVXOp::Mul;
    case FNV1a64("and"): return SVXOp::And;
    case FNV1a64("or"): return SVXOp::Or;
    case FNV1a64("shl"): return SVXOp::Shl;
    case FNV1a64("lshr"): return SVXOp::LShr;
    case FNV1a64("ashr"): return SVXOp::AShr;
    case FNV1a64("udiv"): return SVXOp::UDiv;
    case FNV1a64("sdiv"): return SVXOp::SDiv;
    case FNV1a64("urem"): return SVXOp::URem;
    case FNV1a64("srem"): return SVXOp::SRem;
    default: return SVXOp::Unknown;
    }
}

static int64_t ExecOp(SVXOp op, int64_t a, int64_t b)
{
    const uint64_t ua = static_cast<uint64_t>(a);
    const uint64_t ub = static_cast<uint64_t>(b);
    switch (op)
    {
    case SVXOp::Add: return static_cast<int64_t>(ua + ub);
    case SVXOp::Sub: return static_cast<int64_t>(ua - ub);
    case SVXOp::Xor: return static_cast<int64_t>(ua ^ ub);
    case SVXOp::Mul: return static_cast<int64_t>(ua * ub);
    case SVXOp::And: return static_cast<int64_t>(ua & ub);
    case SVXOp::Or: return static_cast<int64_t>(ua | ub);
    case SVXOp::Shl: return static_cast<int64_t>(ua << (ub & 63));
    case SVXOp::LShr: return static_cast<int64_t>(ua >> (ub & 63));
    case SVXOp::AShr: return a >> (b & 63);
    case SVXOp::UDiv: return b ? static_cast<int64_t>(ua / ub) : 0;
    case SVXOp::SDiv:
        if (b == 0) return 0;
        if (a == INT64_MIN && b == -1) return INT64_MIN;
        return a / b;
    case SVXOp::URem: return b ? static_cast<int64_t>(ua % ub) : 0;
    case SVXOp::SRem:
        if (b == 0) return 0;
        if (a == INT64_MIN && b == -1) return 0;
        return a % b;
    default: return 0;
    }
}

static void SkipWS(const std::string& body, size_t& p)
{
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t' || body[p] == '\n' || body[p] == '\r')) ++p;
}

static std::pair<size_t, size_t> FindJSONString(const std::string& body, const std::string& key, size_t from = 0)
{
    const std::string keyq = "\"" + key + "\"";
    auto k = body.find(keyq, from);
    if (k == std::string::npos) return { std::string::npos, std::string::npos };
    size_t p = k + keyq.size();
    SkipWS(body, p);
    if (p >= body.size() || body[p] != ':') return { std::string::npos, std::string::npos };
    ++p;
    SkipWS(body, p);
    if (p >= body.size() || body[p] != '"') return { std::string::npos, std::string::npos };
    ++p;
    auto end = body.find('"', p);
    if (end == std::string::npos) return { std::string::npos, std::string::npos };
    return { p, end };
}

static int64_t FindJSONInt(const std::string& body, const std::string& key, size_t from = 0)
{
    const std::string keyq = "\"" + key + "\"";
    auto k = body.find(keyq, from);
    if (k == std::string::npos) return -1;
    size_t p = k + keyq.size();
    SkipWS(body, p);
    if (p >= body.size() || body[p] != ':') return -1;
    ++p;
    SkipWS(body, p);
    size_t numstart = p;
    if (p < body.size() && body[p] == '-') ++p;
    while (p < body.size() && std::isdigit(static_cast<unsigned char>(body[p]))) ++p;
    if (p == numstart) return -1;
    try
    {
        return std::stoll(body.substr(numstart, p - numstart));
    }
    catch (...)
    {
        return -1;
    }
}

static std::vector<std::string> FindJSONStringArray(const std::string& body, const std::string& key, size_t from = 0, size_t* outend = nullptr)
{
    std::vector<std::string> result;
    const std::string keyq = "\"" + key + "\"";
    auto k = body.find(keyq, from);
    if (k == std::string::npos) return result;
    size_t p = k + keyq.size();
    SkipWS(body, p);
    if (p >= body.size() || body[p] != ':') return result;
    ++p;
    SkipWS(body, p);
    if (p >= body.size() || body[p] != '[') return result;
    ++p;
    while (true)
    {
        SkipWS(body, p);
        if (p >= body.size()) return result;
        if (body[p] == ']') { ++p; break; }
        if (body[p] != '"') return result;
        ++p;
        auto end = body.find('"', p);
        if (end == std::string::npos) return result;
        result.push_back(body.substr(p, end - p));
        p = end + 1;
        SkipWS(body, p);
        if (p >= body.size()) return result;
        if (body[p] == ',') { ++p; continue; }
        if (body[p] == ']') { ++p; break; }
        return result;
    }
    if (outend) *outend = p;
    return result;
}

using SiteKey = std::array<uint8_t, 16>;
using SessionKey = std::array<uint8_t, 16>;

struct SiteKeyHash
{
    size_t operator()(const SiteKey& k) const noexcept
    {
        uint64_t a, b;
        std::memcpy(&a, k.data(), 8);
        std::memcpy(&b, k.data() + 8, 8);
        return a ^ (b * 0x9E3779B97F4A7C15ull);
    }
};

static int Nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool HexToBytes16(const std::string& hex, SiteKey& out)
{
    if (hex.size() != 32) return false;
    for (int i = 0; i < 16; ++i)
    {
        int hi = Nibble(hex[2 * i]);
        int lo = Nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static void Bytes16ToHex(const uint8_t* b, char out[33])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i)
    {
        out[2 * i] = hex[(b[i] >> 4) & 0xf];
        out[2 * i + 1] = hex[b[i] & 0xf];
    }
    out[32] = 0;
}

struct SiteInfo
{
    SVXOp op;
    uint32_t fnindex;
    std::vector<SiteKey> deps;
};

class ManifestStore
{
public:
    void SetPath(std::string path)
    {
        mpath = std::move(path);
    }

    // Hand back a shared_ptr snapshot so a request thread holds a stable view of the manifest across its dep check even if a concurrent reload swaps msites mid flight; a raw pointer or reference would race the std::shared_ptr assignment in MaybeReloadLocked
    std::shared_ptr<const std::unordered_map<SiteKey, SiteInfo, SiteKeyHash>> Snapshot()
    {
        std::lock_guard<std::mutex> lk(mmtx);
        MaybeReloadLocked();
        return msites;
    }

    void LoadInitial()
    {
        std::lock_guard<std::mutex> lk(mmtx);
        MaybeReloadLocked();
        std::cerr << "[svxserver] manifest initial load: " << (msites ? msites->size() : 0) << " sites from " << mpath << "\n";
    }

private:
    void MaybeReloadLocked()
    {
        std::error_code ec;
        auto now = fs::last_write_time(mpath, ec);
        if (ec)
        {
            if (msites && !msites->empty())
            {
                std::cerr << "[svxserver] manifest disappeared, clearing " << msites->size() << " sites\n";
                msites = std::make_shared<decltype(msites)::element_type>();
                mmtime = {};
            }
            return;
        }
        if (now == mmtime && msites) return;

        auto next = std::make_shared<std::unordered_map<SiteKey, SiteInfo, SiteKeyHash>>();
        std::ifstream f(mpath);
        if (!f)
        {
            std::cerr << "[svxserver] manifest open failed on reload: " << mpath << "\n";
            return;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        const std::string body = ss.str();

        // A manifest with no "version" key (v1 era) parses as -1 and proceeds without gating; a stale v1 manifest paired with a v2 client silently loses per-session dep enforcement; harden to a hard-reject once v1 is retired
        int64_t schema = FindJSONInt(body, "version");
        if (schema != -1 && schema != 2)
        {
            std::cerr << "[svxserver] manifest schema v" << schema << " (server expects v2) — proceeding with best-effort parse\n";
        }

        size_t p = 0;
        unsigned malformed = 0;
        while (true)
        {
            auto [idstart, idend] = FindJSONString(body, "id", p);
            if (idstart == std::string::npos) break;
            auto [opstart, opend] = FindJSONString(body, "op", idend);
            if (opstart == std::string::npos) break;

            const std::string idhex = body.substr(idstart, idend - idstart);
            const std::string ops = body.substr(opstart, opend - opstart);

            size_t rowend = body.find("\"id\":", opend);
            if (rowend == std::string::npos) rowend = body.size();
            std::string rowbody = body.substr(opend, rowend - opend);

            int64_t fnval = FindJSONInt(rowbody, "fn");
            uint32_t fnindex = (fnval < 0) ? 0u : static_cast<uint32_t>(fnval);

            auto depshex = FindJSONStringArray(rowbody, "deps");

            SiteKey key;
            if (!HexToBytes16(idhex, key))
            {
                ++malformed;
                p = opend + 1;
                continue;
            }
            SVXOp op = ParseOp(ops);
            if (op == SVXOp::Unknown)
            {
                ++malformed;
                p = opend + 1;
                continue;
            }

            SiteInfo info;
            info.op = op;
            info.fnindex = fnindex;
            info.deps.reserve(depshex.size());
            for (auto& dh : depshex)
            {
                SiteKey dkey;
                if (HexToBytes16(dh, dkey)) info.deps.push_back(dkey);
                else ++malformed;
            }
            next->emplace(key, std::move(info));
            p = opend + 1;
        }

        const size_t before = msites ? msites->size() : 0;
        msites = next;
        mmtime = now;
        std::cerr << "[svxserver] manifest reloaded: " << before << " -> " << msites->size() << " sites (mtime changed)";
        if (malformed) std::cerr << " [" << malformed << " malformed row(s) skipped]";
        std::cerr << "\n";
    }

    std::string mpath;
    std::mutex mmtx;
    std::shared_ptr<const std::unordered_map<SiteKey, SiteInfo, SiteKeyHash>> msites = std::make_shared<std::unordered_map<SiteKey, SiteInfo, SiteKeyHash>>();
    fs::file_time_type mmtime{};
};

static ManifestStore GManifest;

// SessionStore never purges! A long running server accumulates one SessionState per unique (16-byte) sessionid
class SessionStore
{
public:
    enum Result
    {
        Fired,
        OrderViolation,
    };

    Result CheckAndFire(const SessionKey& sess, const SiteKey& site, const SiteInfo& info)
    {
        std::lock_guard<std::mutex> lk(mmtx);
        auto& firedinfn = msessions[sess].fired[info.fnindex];
        for (const auto& dep : info.deps)
        {
            if (!firedinfn.count(dep)) return OrderViolation;
        }
        firedinfn.insert(site);
        return Fired;
    }

private:
    struct SessionState
    {
        std::unordered_map<uint32_t, std::unordered_set<SiteKey, SiteKeyHash>> fired;
    };

    std::unordered_map<SessionKey, SessionState, SiteKeyHash> msessions;
    std::mutex mmtx;
};

static SessionStore GSessions;

static void HandleSession(tcp::socket socket)
{
    boost::system::error_code ec;
    socket.set_option(tcp::no_delay(true), ec);

    SvxRequest req{};
    size_t n = net::read(socket, net::buffer(&req, sizeof(req)), ec);
    if (ec || n != sizeof(req)) return;

    if (req.version != SVXWireVersion)
    {
        static bool warnedonce = false;
        if (!warnedonce)
        {
            std::cerr << "[svxserver] client sent wire version " << static_cast<unsigned>(req.version) << " (expected " << static_cast<unsigned>(SVXWireVersion) << "); closing. Further mismatches silenced.\n";
            warnedonce = true;
        }
        return;
    }

    SiteKey site;
    std::memcpy(site.data(), req.siteid, 16);
    SessionKey sess;
    std::memcpy(sess.data(), req.sessionid, 16);

    auto manifest = GManifest.Snapshot();
    auto it = manifest->find(site);

    SvxReply reply{};
    if (it == manifest->end())
    {
        char hex[33];
        Bytes16ToHex(req.siteid, hex);
        std::cerr << "[svxserver] unknown site: " << hex << "\n";
        reply.status = SVXStatusUnknownSite;
    }
    else
    {
        auto fire = GSessions.CheckAndFire(sess, site, it->second);
        if (fire == SessionStore::OrderViolation)
        {
            char sitehex[33];
            Bytes16ToHex(req.siteid, sitehex);
            char sesshex[33];
            Bytes16ToHex(req.sessionid, sesshex);
            std::cerr << "[svxserver] ORDER VIOLATION site=" << sitehex << " session=" << sesshex << " fn=" << it->second.fnindex << " unmetdeps=" << it->second.deps.size() << "\n";
            reply.status = SVXStatusOrderViolation;
        }
        else
        {
            reply.result = ExecOp(it->second.op, req.a, req.b);
            reply.status = SVXStatusOk;
        }
    }

    net::write(socket, net::buffer(&reply, sizeof(reply)), ec);
    socket.shutdown(tcp::socket::shutdown_send, ec);
}

int main(int argc, char** argv)
{
    const std::string bind = (argc > 1) ? argv[1] : DefaultBind;
    const unsigned short port = (argc > 2) ? static_cast<unsigned short>(std::atoi(argv[2])) : DefaultPort;
    const std::string manifest = (argc > 3) ? argv[3] : DefaultManifest;

    GManifest.SetPath(manifest);
    GManifest.LoadInitial();

    try
    {
        net::io_context ioc;
        tcp::acceptor acceptor{ ioc, {net::ip::make_address(bind), port} };
        std::cerr << "[svxserver] listening on " << bind << ":" << port << "\n";
        for (;;)
        {
            tcp::socket socket{ ioc };
            acceptor.accept(socket);
            std::thread(&HandleSession, std::move(socket)).detach();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "[svxserver] fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}