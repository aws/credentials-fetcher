# CMake generated Testfile for 
# Source directory: /Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode
# Build directory: /Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(check_help "/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/build/credentials-fetcherd" "--help")
set_tests_properties(check_help PROPERTIES  WILL_FAIL "TRUE" _BACKTRACE_TRIPLES "/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/CMakeLists.txt;161;add_test;/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/CMakeLists.txt;0;")
add_test(run_self_test "/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/build/credentials-fetcherd" "--self_test")
set_tests_properties(run_self_test PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/CMakeLists.txt;162;add_test;/Users/awsjohns/credentials-fetcher2/credentials-fetcher/no-grpc-mode/CMakeLists.txt;0;")
subdirs("config")
subdirs("renewal")
subdirs("metadata")
subdirs("auth")
subdirs("daemon")
