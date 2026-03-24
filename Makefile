CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
TARGET   = ipk-l2l3-scan
SRCDIR   = src
BUILDDIR = build

SRCS = $(SRCDIR)/main.cpp $(SRCDIR)/subnet.cpp $(SRCDIR)/netif.cpp
OBJS = $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR) $(TARGET)
