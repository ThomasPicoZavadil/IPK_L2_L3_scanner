/**
 * @file result_printer.hpp
 * @brief Abstract base class for protocol-specific result printers.
 *
 * Each derived printer knows how to format one kind of scan result
 * (ARP, NDP, ICMPv4, …) for output.
 */
#ifndef RESULT_PRINTER_HPP
#define RESULT_PRINTER_HPP

#include <string>

/**
 * @brief Interface for printing scan results per protocol.
 */
class ResultPrinter {
public:
    virtual ~ResultPrinter() = default;

    /**
     * @brief Print a successful result (host responded).
     * @param ip   The target IP address.
     * @param mac  The resolved MAC address.
     */
    virtual void print_ok(const std::string& ip,
                          const std::string& mac) = 0;

    /**
     * @brief Print a failed result (no response received).
     * @param ip  The target IP address.
     */
    virtual void print_fail(const std::string& ip) = 0;
};

#endif // RESULT_PRINTER_HPP
