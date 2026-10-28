# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# cysec-fake-engine: a Qt Core console stand-in for the scanner CLI. It
# replays NDJSON fixtures and simulates every end state (completed, cooperative
# cancel on stdin EOF, stubborn child, stderr flood) so the process transport
# is tested on every OS without a network.

qt_add_executable(cysec-fake-engine main.cpp)
target_link_libraries(cysec-fake-engine PRIVATE Qt6::Core)
set_target_properties(cysec-fake-engine PROPERTIES MACOSX_BUNDLE OFF WIN32_EXECUTABLE OFF)
