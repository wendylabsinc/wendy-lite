# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Pull wendy-lite's components in from its checkout on disk instead of
# vendoring copies here. Points at the local clone of
# github.com:wendylabsinc/wendy-lite, a sibling checkout
# of this project.
#set(EXTRA_COMPONENT_DIRS
#    "${CMAKE_CURRENT_LIST_DIR}/../wendy-lite/components"
#)

# Wendy Lite: the configuration of the device (sdkconfig.defaults.wendy), then the app's own defaults, which win.
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults.wendy;sdkconfig.defaults")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(blink-rgb)
