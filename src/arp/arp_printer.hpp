/**
 * @file arp_printer.hpp
 * @brief ArpPrinter - formats ARP scan results for output.
 */
#ifndef ARP_PRINTER_HPP
#define ARP_PRINTER_HPP

#include "result_printer.hpp"

#include <iostream>
#include <string>

/**
 * @brief Prints ARP scan results to stdout.
 */
class ArpPrinter : public ResultPrinter {
public:
    void print_ok(const std::string& ip,
                  const std::string& mac) override
    {
        std::cout << ip << " arp OK (" << mac << ")\n";
    }

    void print_fail(const std::string& ip) override
    {
        std::cout << ip << " arp FAIL\n";
    }
};

#endif // ARP_PRINTER_HPP
