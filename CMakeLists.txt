cmake_minimum_required(VERSION 2.8.4)
project(pof-cbench)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        cbench.c
        cbench.h
        fakeswitch.c
        fakeswitch.h
        msgbuf.c
        msgbuf.h
        myargs.c
        myargs.h
        pof.h)

add_executable(pof-cbench ${SOURCE_FILES})

target_link_libraries(pof-cbench m)

install(TARGETS pof-cbench DESTINATION bin)