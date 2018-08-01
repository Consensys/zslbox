
add_library(
  zsl
  STATIC
  zsl.cpp
)

target_link_libraries(
  zsl

  snark
  # ff
  # ${GMP_LIBRARIES}
  # ${GMPXX_LIBRARIES}
  # ${CRYPTO_LIBRARIES}
  # ${PROCPS_LIBRARIES}
  # ${SNARK_EXTRALIBS}
)

# install(
#   DIRECTORY "" DESTINATION "include/libsnark"
#   FILES_MATCHING
#   PATTERN "*.hpp"
#   PATTERN "*.tcc"
#   PATTERN "tests" EXCLUDE
#   PATTERN "examples" EXCLUDE
# )

install(
  TARGETS
  zsl

  DESTINATION lib
)

