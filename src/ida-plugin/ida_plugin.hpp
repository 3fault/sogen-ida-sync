#pragma once

#include <pro.h>
#include <algorithm>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>

#include <format>

struct ida_local load_pdb_t : public exec_request_t 
{
    load_pdb_t(const void* mod_name, nodeidx_t base_addr) : 
        mod_name_(mod_name), base_addr_(base_addr) 
    { 
    }

    ssize_t idaapi execute() override
    {
    	// Set parameters for PDB plugin
    	auto net_node = netnode("$ pdb");
    	net_node.altset(0, base_addr_);
    	net_node.supset(0, mod_name_); // SYSTEM32_COPY_PATH

    	//Use 1 to get a confirmation prompt
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

inline bool set_env_nt_symbol_path(const char* path = "SRV*c:\\symbols*http://msdl.microsoft.com/download/symbols")
{
    return qsetenv("_NT_SYMBOL_PATH", path); 
}

static void print_string_view(const std::string_view& str)
{
	msg("sogen-sync: %.*s\n", static_cast<int>(str.length()), str.data());
}

static std::vector<std::string_view> split(const std::string_view str, const char delim = ',')
{   
    std::vector<std::string_view> result;

    int indexCommaToLeftOfColumn = 0;
    int indexCommaToRightOfColumn = -1;

    for (int i=0;i<static_cast<int>(str.size());i++)
    {
        if (str[i] == delim)
        {
	            indexCommaToLeftOfColumn = indexCommaToRightOfColumn;
	            indexCommaToRightOfColumn = i;
	            int index = indexCommaToLeftOfColumn + 1;
	            int length = indexCommaToRightOfColumn - index;

	            std::string_view column(str.data() + index, length);
	            result.push_back(column);
        }
    }
	
    const std::string_view finalColumn(str.data() + indexCommaToRightOfColumn + 1, str.size() - indexCommaToRightOfColumn - 1);
    result.push_back(finalColumn);
    return result;
}

enum LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

// https://stackoverflow.com/questions/79359256/text-formatting-using-stdformat-for-enums
template<> struct std::formatter<LogLevel> : std::formatter<std::string>
{
    constexpr auto format(const LogLevel& level, auto& ctx) const
    {
        using Base = std::formatter<std::string>;
        
        auto fmt_str = std::to_string(level);
        std::ranges::transform(fmt_str, fmt_str.begin(), ::toupper);
        
        return Base::format(fmt_str, ctx);      
    }
};

// template<> struct std::formatter<std::string_view> : std::formatter<std::string>
// {
//     constexpr auto format(const std::string_view& str_view, auto& ctx) const
//     {
//         const auto fmt = std::format("{%.*s}", static_cast<int>(str_view.length()), str_view.data());
//         return formatter<string>::format(fmt, ctx);
//     }
// };

// Formatted logging function using std::format
template<typename... Args>
static void ida_log(LogLevel level, std::string_view format_str = "", Args&&... args) 
{
    // Format the message using std::format
    std::string formatted_message = std::vformat(format_str, std::make_format_args(args...));

    // Get current time (simplified for brevity)
    // std::string timestamp = "YYYY-MM-DD HH:MM:SS"; // Replace with actual time retrieval

    // Output to console (or file, etc.)
    // std::cout << "[" << timestamp << "] [" << logLevelToString(level) << "] " << formatted_message << std::endl;
    msg("sogen-sync %s: %s\n", level, formatted_message);
}
