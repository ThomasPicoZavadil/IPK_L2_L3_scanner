CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
TARGET   = ipk-L2L3-scan
SRCDIR   = src
BUILDDIR = build

SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/subnet.cpp $(SRCDIR)/netif.cpp $(SRCDIR)/arp/arp_crafter.cpp $(SRCDIR)/pcap_engine.cpp $(SRCDIR)/arp/arp_listener.cpp $(SRCDIR)/icmpv4/icmpv4_crafter.cpp $(SRCDIR)/icmpv4/icmpv4_listener.cpp $(SRCDIR)/scan_result_manager.cpp $(SRCDIR)/ndp/ndp_crafter.cpp $(SRCDIR)/ndp/ndp_listener.cpp
OBJS = $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap -lpthread

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

NixDevShellName:
	@echo c

clean:
	rm -rf $(BUILDDIR) $(TARGET)
