cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(ida-sogen-sync)

file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
  *.rc
)

list(SORT SRC_FILES)

set(CMAKE_CXX_STANDARD 20)
set(TEST_SAMPLE "${CMAKE_BINARY_DIR}/artifacts-$(Configuration)/test-sample.exe.i64")

set(PLUGIN_NAME           ida-sogen-sync)  # The project name. It is also used as the binary name if the `PLUGIN_OUTPUT_NAME` is absent.
set(PLUGIN_SOURCES        ${SRC_FILES})    # Space seperated list of source files that make up the plugin.
set(PLUGIN_LINK_LIBRARIES emulator-common) # Additional link libraries used by the plugin.

# `PLUGIN_RUN_ARGS` specify the default command line arguments to pass when
# you run your plugins from the IDE (only works with Visual Studio). If not
# specified, then IDA will run with a temporary database (-t switch).
#
# https://docs.hex-rays.com/user-guide/configuration/command-line-switches
#
# -z1000  Debug messages for the debugger 
# -A      Autonomous mode. IDA will not display dialog boxes. Designed to be
#         used together with -S switch.
# -r      Runs the built-in debugger without creating a database in advance.#
set(PLUGIN_RUN_ARGS          "-z10000 -rgdb@127.0.0.1:28960 ${TEST_SAMPLE}")

generate()

disable_ida_warnings(ida-sogen-sync)

momo_strip_target(ida-sogen-sync)
