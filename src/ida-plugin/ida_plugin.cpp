#include "ida_plugin.hpp"
#include "network/socket.hpp"
#include "pro.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <netnode.hpp>
// #include <kernwin.hpp>
#include <dbg.hpp>

#include <cstdlib>
#include <cassert>
#include <cinttypes>

#include <ranges>
#include <string>
#include <utils/string.hpp>
#include <platform/compiler.hpp>
#include <network/tcp_client_socket.hpp>

static network::tcp_client_socket client_;

// Define the class that inherits from plugmod_t
class MyPlugmod : public plugmod_t, public event_listener_t
{
public:
	// Constructor
	MyPlugmod() 
	{
		ida_log(LogLevel::Info, "Constructor called.\n");
		// msg("MyPlugmod: Constructor called.\n");
		// https://docs.hex-rays.com/developer-guide/c++-sdk/c++-sdk-examples#ex_events1
		// https://cpp.docs.hex-rays.com/group__dbg__funcs.html
		// https://securelist.com/great-ida-pro-plugins/97898/
		// hook_event_listener(HT_DBG, this);
		// hook_to_notification_point(HT_DBG, ht_dbg_callback);
		
	}

	// static ssize_t ht_dbg_callback(void *user_data, int notification_code, va_list va)
	// {
	// 	return 0;
	// }

	// Destructor
	~MyPlugmod() override 
	{
		ida_log(LogLevel::Info, "Destructor called.\n");
	}
	
	static void process_packet(const std::string_view packet)
	{
		print_string_view(packet);

		auto tokens = split(packet, ':');

		// auto iter = tokens.begin();
		// while(iter != tokens.end())
		// {
		// 	size_t i = std::distance(std::begin(tokens), iter);
		// 	auto command = tokens[i];

		// 	if (command == "module_load")
		// 	{
		// 		const auto mod_name = std::format(R"(C:\Windows\System32\{})", tokens[i + 1]);

		// 		auto base_addr = nodeidx_t{0};
		// 		if (std::from_chars(tokens[i+2].data(), tokens[i+2].data() + tokens[i+2].size(), base_addr).ec == std::errc::invalid_argument)
		// 		{
		// 			msg("sogen-sync: Failed to parse base address (%.*s)\n", static_cast<int>(tokens[i+2].length()), tokens[i+2].data());
					
		// 		}
				
		// 		std::advance(iter, 3);
		// 	}
		// }

		auto command = tokens[0];

		if (command == "module_load")
		{			
			const auto mod_name = std::format(R"(C:\Windows\System32\{})", tokens[1]);
			
			const auto base_addr = tokens[2];
			print_string_view(base_addr);

			auto base_addr_node = nodeidx_t{0};
			
			auto parse_result = std::from_chars(
				base_addr.data(), 
				base_addr.data() + base_addr.size(), 
				base_addr_node
			);
			
			if (parse_result.ec == std::errc::invalid_argument) 
			{
				ida_log(LogLevel::Error, 
					"Failed to parse base address (%.*s)", 
					static_cast<int>(base_addr.length()), base_addr.data());
			}
			
			// suspend_process();
			
			load_pdb_t pdb_loader{mod_name.c_str(), base_addr_node};
			execute_sync(pdb_loader, MFF_WRITE);			
		}		
	}
	
	static int thread_func(void *ud)
	{
		// auto id = (size_t)ud;
		// qthread_t tid = qthread_self();
		
		while (true)
		{
			const auto packet = client_.receive();
			if (!packet) 
			{
				break;
			}

			process_packet(*packet);

			qsleep(100);
		}
		return 0;
	}

	// Method that gets called when the plugin is activated
	bool idaapi run(size_t arg) override
	{
		msg("MyPlugmod.run() called with arg: %d\n", arg);
		
		// if (!set_env_nt_symbol_path())
		// {
		// 	ida_log(LogLevel::Error, "_NT_SYMBOL_PATH not set!");
		// }
						
		const auto address = network::address{"127.0.0.1:28961", AF_INET};
		client_ = network::tcp_client_socket{address.get_family()};
		
		if (!client_.connect(address)) 
		{
			const auto error = GET_SOCKET_ERROR();
			msg("Could not connect to server: %d\n", error);
			return false;
		};
		
		ida_log(LogLevel::Info, "sogen-sync: Connected!");

		// https://docs.hex-rays.com/developer-guide/c++-sdk/c++-sdk-examples#mtsample
		t_ = qthread_create(thread_func, (void*)(ssize_t)n_childs_); n_childs_++;
		
		return true;
	}

	ssize_t idaapi on_event(ssize_t event_id, va_list) override
	{
		// switch (event_id)
		// {
		// 	case dbg_not
		// }
		// 0 means "continue processing the event", otherwise the event
		// is considered as processed
		return 0;
	}

private:
	qthread_t t_;
	int n_childs_ = 0;
};

static plugmod_t* idaapi init()
{
	return new MyPlugmod();
}

plugin_t PLUGIN =
{
  .version = IDP_INTERFACE_VERSION,
  .flags = PLUGIN_MULTI,         // plugin flags
  .init = init,                 // initialize
  .term = nullptr,              // terminate. this pointer can be nullptr
  .run = nullptr,              // invoke the plugin
  .comment = nullptr,              // long comment about the plugin
  .help = nullptr,              // multiline help about the plugin
  .wanted_name = "Sogen",		// the preferred short name of the plugin
  .wanted_hotkey = ""					// the preferred hotkey to run the plugin
};
