cmake_minimum_required(VERSION 3.10)

project(ZoomClient)

set(CMAKE_CXX_STANDARD 20)

# إخبار المترجم باستخدام Unicode
add_definitions(-DUNICODE -D_UNICODE)

# إضافة ملف الكود الرئيسي
add_library(ZoomClient SHARED main.cpp)

# مكتبات الويندوز الضرورية
if(WIN32)
    target_link_libraries(ZoomClient PRIVATE user32 kernel32)
endif()
