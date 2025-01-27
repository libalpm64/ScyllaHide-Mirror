#define USE_STANDARD_FILE_FUNCTIONS
#pragma warning(disable : 4996 4512 4127 4201 4244 4267)

#define BUILD_IDA_64BIT 1


//for 64bit - p64
//#ifdef BUILD_IDA_64BIT
#define __EA64__
#pragma comment(lib, "./idasdk70/lib/x64_win_vc_64/ida.lib")
//#else
////for 32bit - plw
//#pragma comment(lib, "./idasdk70/lib/x64_win_vc_32/ida.lib")
//#endif

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>