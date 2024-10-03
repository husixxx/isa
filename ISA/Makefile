# Makefile

# Kompilátor
CXX = g++

# Štandard C++
CXXFLAGS = -std=c++17 -Wall

# Výstupný súbor (názov výsledného programu)
TARGET = main

# Zoznam zdrojových súborov
SRCS = main.cpp helper.cpp dnsMonitor.cpp

# Automatická tvorba objektových súborov
OBJS = $(SRCS:.cpp=.o)

# Pravidlo pre kompiláciu (výstupný súbor)
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) -lpcap

# Pravidlo pre kompiláciu jednotlivých .cpp na .o (objektové súbory)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Vyčistenie objektových súborov a binárky
clean:
	rm -f $(OBJS) $(TARGET)

# Aby sa Makefile nesnažil vytvoriť súbor "clean"
.PHONY: clean
