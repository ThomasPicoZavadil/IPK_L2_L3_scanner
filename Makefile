CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
TARGET   = ipk-L2L3-scan
SRCDIR   = src
BUILDDIR = build

SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/subnet.cpp $(SRCDIR)/netif.cpp $(SRCDIR)/arp/arp_crafter.cpp $(SRCDIR)/pcap_engine.cpp $(SRCDIR)/arp/arp_listener.cpp $(SRCDIR)/icmpv4/icmpv4_crafter.cpp $(SRCDIR)/icmpv4/icmpv4_listener.cpp $(SRCDIR)/scan_result_manager.cpp $(SRCDIR)/ndp/ndp_crafter.cpp $(SRCDIR)/ndp/ndp_listener.cpp $(SRCDIR)/icmpv6/icmpv6_crafter.cpp $(SRCDIR)/icmpv6/icmpv6_listener.cpp
OBJS = $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap -lpthread

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# ── Unit tests (GTest) ──────────────────────────────────────────────────────
TEST_TARGET = run_tests
TEST_SRCS   = tests/test_cidr.cpp tests/test_packets.cpp \
              $(SRCDIR)/subnet.cpp $(SRCDIR)/scan_result_manager.cpp \
              $(SRCDIR)/arp/arp_listener.cpp $(SRCDIR)/icmpv4/icmpv4_listener.cpp \
              $(SRCDIR)/ndp/ndp_listener.cpp $(SRCDIR)/icmpv6/icmpv6_listener.cpp

$(TEST_TARGET): $(TEST_SRCS)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -o $@ $^ -lgtest -lgtest_main -pthread

test: $(TEST_TARGET)
	./$(TEST_TARGET)

NixDevShellName:
	@echo c

clean:
	rm -rf $(BUILDDIR) $(TARGET) $(TEST_TARGET)
