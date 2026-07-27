cmake_minimum_required(VERSION 3.10)
project(RealWorldApp C)

include_directories(include)

add_executable(real_world_app
    src/main.c
    src/auth.c
    src/crypto.c
)
