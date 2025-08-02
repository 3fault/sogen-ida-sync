#pragma once

#include "dbg.hpp"
#include "idd.hpp"
#include "network/tcp_client_socket.hpp"
#include "segment.hpp"
#include <pro.h>
#include <algorithm>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>

#include <ranges>
#include <format>
#include <cinttypes>

// Suppress compiler warnings about unused variables
#define UNUSED(...) (void)sizeof(__VA_ARGS__)

enum LogLevel
{
    Debug,
    Info,
    Warning,
    Error
};

constexpr const char* log_level_str(LogLevel level) noexcept
{
    switch (level)
    {
    case Debug:
        return "DEBUG";
    case Info:
        return "INFO";
    case Warning:
        return "WARNING";
    case Error:
        return "ERROR";
    default:
        return "";
    }
}

// https://stackoverflow.com/questions/79359256/text-formatting-using-stdformat-for-enums
template <>
struct std::formatter<LogLevel> : std::formatter<std::string>
{
    constexpr auto format(const LogLevel& level, auto& ctx) const
    {
        // auto fmt_str = std::to_string(level);
        // std::ranges::transform(fmt_str, fmt_str.begin(), ::toupper);

        // return std::formatter<std::string>::format(fmt_str, ctx);

        const auto* fmt_str = log_level_str(level);
        // std::ranges::transform(fmt_str, fmt_str.begin(), ::toupper);

        return std::formatter<std::string>::format(fmt_str, ctx);
    }
};

// Formatted logging function using std::format
template <typename... Args>
static void ida_log(LogLevel level, std::string_view format_str = "", Args&&... args)
{
    // const auto fmt_str = std::vformat(
    //     "sogen-sync {}: {}\n",
    //     std::make_format_args(level, format_str, args...)
    // );

    // msg("%s", fmt_str.c_str());

    const auto fmt_str = std::vformat(format_str, std::make_format_args(args...));
    msg("sogen-sync %s: %s\n", log_level_str(level), fmt_str.c_str());
}

// struct ida_local module_request_t : public exec_request_t
// {
// public:
//     module_request_t(const char* mod_name, ea_t base_addr, auto request)
//         : mod_name_(mod_name), base_addr_(base_addr), request_(request) {}

//     ssize_t idaapi execute() override
//     {
//         // Somehow get mod_name_ and base_addr_ in here generically, std::forward???
//         success_ = request_();
//         return 0;
//     }

// private:
//     bool success_ = false;
//     const char* mod_name_;
//     const ea_t base_addr_;
//     const std::function<bool()> request_ = nullptr;
// }

struct ida_local add_module_req_t : public exec_request_t
{
    add_module_req_t(const char* path, size_t address, size_t size)
        : path_(path),
          address_(address),
          size_(size)
    {
    }

    ssize_t idaapi execute() override
    {
        modinfo_t module{.name = path_, .base = address_, .size = size_};

        if (!add_virt_module(&module))
        {
            ida_log(LogLevel::Error, "Failed to add virtual module %s @ 0x" PRIx64, path_, address_);

            return 1;
        }

        return 0;
    }

    const char* path_;
    size_t address_;
    size_t size_;
};

struct ida_local load_pdb_t : public exec_request_t
{
    load_pdb_t(const void* mod_name, nodeidx_t base_addr)
        : mod_name_(mod_name),
          base_addr_(base_addr)
    {
    }

    ssize_t idaapi execute() override
    {
        // Set parameters for PDB plugin
        auto net_node = netnode("$ pdb");
        net_node.altset(0, base_addr_);
        net_node.supset(0, mod_name_); // SYSTEM32_COPY_PATH

        // Use 1 to get a confirmation prompt
        if (!load_and_run_plugin("pdb", 3))
        {
            msg("Failed to run PDB plugin");
        }
        else
        {
            msg("sogen-sync: Finished PDB plugin");
        }

        return 0;
    }

    const void* mod_name_;
    nodeidx_t base_addr_;
};

struct ida_local add_segm_req_t : public exec_request_t
{
    add_segm_req_t(const char* mod_name, size_t base_addr, size_t size_of_image, const char* perms)
        : mod_name_(mod_name),
          base_addr_(base_addr),
          size_of_image_(size_of_image),
          perms_(map_rwx_to_ida_protection(perms))
    {
    }

    static uint8_t map_rwx_to_ida_protection(const char* perms)
    {
        // TODO: Safety
        const bool has_read = perms[0] == 'r';
        const bool has_write = perms[1] == 'w';
        const bool has_exec = perms[2] == 'x';

        uint8_t res = 0;

        if (has_read)
            res += SEGPERM_READ;
        if (has_write)
            res += SEGPERM_WRITE;
        if (has_exec)
            res += SEGPERM_EXEC;

        return res;
    }

    ssize_t idaapi execute() override
    {
        auto* const segment = getseg(base_addr_);
        if (segm_exists(segment))
        {
            ida_log(LogLevel::Info, "Segment '{}' @ {:#x} already exists", mod_name_, base_addr_);
            return 0;
        }

        // Allocate a selector for the segment if necessary
        const sel_t selector = setup_selector(base_addr_);

        constexpr const ushort segm_flags = SFL_DEBUG; // The segment was created for the debugger
        // if PE header segment, segm_flags |= SFL_HEADER

        // segment_t ns;
        // ns.align = saRelByte;
        // ns.comb = scPriv;
        // ns.perm = perms_;
        // ns.bitness = 2; // Number of bits in the segments addressing (2 is 64-bit)
        // ns.flags = segm_flags; // https://cpp.docs.hex-rays.com/group___s_f_l__.html
        // ns.sel = selector; // Segment selector
        // ns.type = SEG_NORM; // https://cpp.docs.hex-rays.com/group___s_e_g__.html
        // ns.color = 0xFF00FF;
        // ns.start_ea = to_ea(selector, base_addr_);
        // ns.end_ea = to_ea(selector, base_addr_ + size_of_image_);

        // const char* segm_class = nullptr;
        // if (perms_ & SEGPERM_EXEC)
        // {
        //     segm_class = "CODE";
        // }
        // else if (perms_ & SEGPERM_READ && perms_ & SEGPERM_WRITE)
        // {
        //     segm_class = "DATA";
        // } else if (perms_ & SEGPERM_READ) {
        //     segm_class = "CONST";
        // }

        // if (!add_segm_ex(
        //     &ns,
        //     mod_name_,
        //     nullptr, // segm_class
        //     0 // https://cpp.docs.hex-rays.com/group___a_d_d_s_e_g__.html
        // ))
        if (!add_segm(0,
                      base_addr_, // Start address of the segment. If start==BADADDR then start <- to_ea(para, 0);
                      base_addr_ + size_of_image_, mod_name_, nullptr, 0))
        {
            ida_log(LogLevel::Error, "Failed to add '{}' segment @ {:#x}", mod_name_, base_addr_);

            return 0;
        }

        ida_log(LogLevel::Info, "Added '{}' segment @ {:#x}", mod_name_, base_addr_);

        auto* new_segm = getseg(base_addr_);
        if (!new_segm)
        {
            ida_log(LogLevel::Error, "Could not retrieve newly added segment");
            return 0;
        }

        new_segm->set_debugger_segm(true);

        // Set segment permissions READ+WRITE+EXEC.
        // new_segm->perm = SEGPERM_MAXVAL;
        new_segm->perm = perms_;

        // Set segment combination code to private. Do not combine with
        // any other program.
        new_segm->comb = scPriv;

        if (!new_segm->update())
        {
            ida_log(LogLevel::Error, "Unable to update the newly added segment");
            return 0;
        }

        // if (!update_segm(new_segm))
        // {
        //     ida_log(LogLevel::Error, "Unable to update the newly added segment");
        //     return 0;
        // }

        return 0;
    }

    bool segm_exists(const segment_t* segm) const
    {
        if (segm != nullptr)
        {
            const auto segm_base = get_segm_base(segm);
            const auto segm_end = segm_base + segm->end_ea;

            return segm_base == base_addr_ || segm_end == base_addr_ + size_of_image_;
        }

        return false;
    }

    const char* mod_name_;
    size_t base_addr_;
    size_t size_of_image_;
    uint8_t perms_;
};

inline bool set_env_nt_symbol_path(const char* path = "SRV*c:\\symbols*http://msdl.microsoft.com/download/symbols")
{
    return qsetenv("_NT_SYMBOL_PATH", path);
}

static void print_string_view(const std::string_view& str)
{
    msg("sogen-sync: %.*s\n", static_cast<int>(str.length()), str.data());
}

static std::vector<std::string> split_packet(const std::string_view& packet, const char delim)
{
    namespace r = std::ranges;
    namespace rv = r::views;

    // Lambda to convert a sub-range into a std::string
    auto to_string = [](auto&& sub_range) { return std::string(r::begin(sub_range), r::end(sub_range)); };

    // Split and transform
    auto str_range = packet | rv::split(delim) | rv::transform(to_string);

    // C++23 introduces std::ranges::to
    return {r::begin(str_range), r::end(str_range)};
}

static bool initialize_tcp_client(network::tcp_client_socket& client, const char* hostname, int port)
{
    const auto address = network::address{std::format("{}:{}", hostname, port), AF_INET};
    client = network::tcp_client_socket{address.get_family()};

    if (!client.connect(address))
    {
        const auto error = GET_SOCKET_ERROR();
        ida_log(LogLevel::Error, "Unable to connect to sync server on {}:{}: %d", hostname, port, error);
        return false;
    };

    ida_log(LogLevel::Info, "Connected!");
    return true;
}

static std::optional<network::tcp_client_socket> initialize_tcp_client(const char* hostname, int port)
{
    network::tcp_client_socket client;
    if (initialize_tcp_client(client, hostname, port))
    {
        return client;
    }

    return std::nullopt;
}
