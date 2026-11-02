// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/saml.hpp"

namespace iya::saml {

Failure::Failure(std::string kind_in, std::string message) : std::runtime_error(std::move(message)), kind(std::move(kind_in)) {}

Failure Failure::status_error(std::string message, std::string code, std::string sub, std::string text) {
  Failure failure("status", std::move(message));
  failure.status_code = std::move(code);
  failure.status_subcode = std::move(sub);
  failure.status_message = std::move(text);
  return failure;
}

}  // namespace iya::saml
