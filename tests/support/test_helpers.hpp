#ifndef LAMINATE_TESTS_TEST_HELPERS_HPP
#define LAMINATE_TESTS_TEST_HELPERS_HPP

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

namespace laminate::test {

class CheckFailure : public std::exception {
  public:
    explicit CheckFailure(std::string message)
        : message_(std::move(message)) {}

    const char *what() const noexcept override { return message_.c_str(); }

  private:
    std::string message_;
};

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::ostringstream laminate_check_message;                         \
            laminate_check_message << "CHECK failed: " #condition << " ("     \
                                    << __FILE__ << ':' << __LINE__ << ')';     \
            throw ::laminate::test::CheckFailure(                              \
                laminate_check_message.str());                                 \
        }                                                                      \
    } while (false)

class Runner {
  public:
    explicit Runner(std::string suite) : suite_(std::move(suite)) {
        std::cout << "=== " << suite_ << " ===\n";
    }

    void run(const std::string &name, const std::function<void()> &body) {
        try {
            body();
            ++passed_;
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception &error) {
            ++failed_;
            std::cout << "[FAIL] " << name << " - " << error.what() << '\n';
        }
    }

    int summary() const {
        std::cout << suite_ << ": " << passed_ << " passed, " << failed_
                  << " failed\n";
        return failed_;
    }

  private:
    std::string suite_;
    int passed_ = 0;
    int failed_ = 0;
};

} // namespace laminate::test

#endif // LAMINATE_TESTS_TEST_HELPERS_HPP
