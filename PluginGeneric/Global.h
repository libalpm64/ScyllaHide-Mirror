#pragma once

#define COMPILE_TIME_ASSERT(expr) typedef char COMP_TIME_ASSERT[(expr) ? 1 : 0]

