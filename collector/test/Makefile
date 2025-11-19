# Compiler và flags
CC       := cc
CFLAGS   := -g -Wall -O0 -fprofile-arcs -ftest-coverage
LDFLAGS  := -fprofile-arcs -ftest-coverage
INCLUDES := -I../ebpf/include -I..

# Source files
SRC_COLLECTOR   := collector_test.c ../collector_core/collector_core.c ../queue/queue.c ../json_builder/json_builder.c ../time_utils/time_utils.c

# Output
TARGET_COL      := test_collector

# Libraries
LIBS_COL        := -lpthread -lcurl

.PHONY: all clean coverage test

all: $(TARGET_COL)

# Build test_collector
$(TARGET_COL): $(SRC_COLLECTOR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS_COL)

# Run unit tests
test: $(TARGET_COL)
	@echo "Running test_collector..."
	./$(TARGET_COL)

# Generate coverage report
coverage: $(TARGET_COL)
	@echo "Running tests to generate coverage..."
	./$(TARGET_COL)
	@echo "Capturing coverage data..."
	lcov --capture --directory .. --output-file coverage.info
	@echo "Filtering coverage data..."
	lcov --remove coverage.info "*/test/*" "/usr/*" --output-file coverage_filtered.info
	@echo "Generating HTML report..."
	genhtml coverage_filtered.info --output-directory coverage_html
	@echo "Coverage report generated in coverage_html/index.html"

# Clean
clean:
	rm -f $(TARGET_COL) ./*.gcda ./*.gcno coverage.info
	rm -rf coverage_html
