
include_directories(BEFORE .)

add_library(gridinit-utils SHARED
		uid.c
		common.c
		limits.c
		command.c
		children.c
		gridinit-utils.h
		gridinit-internals.h)

target_link_libraries(gridinit-utils
		${GLIB2_LIBRARIES})

set_target_properties(gridinit-utils PROPERTIES
		PUBLIC_HEADER "gridinit-utils.h"
		SOVERSION ${ABI_VERSION})

install(TARGETS gridinit-utils
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include
		RUNTIME DESTINATION bin)

