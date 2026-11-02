// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/saml.hpp"

#include <iostream>
#include <string>

int main() {
  if (iya::saml::caep_events().size() != 8 || iya::saml::risc_events().size() != 14) {
    std::cout << "FAIL event counts\n";
    return 1;
  }
  const char* uri = iya::saml::event_uri("risk_level_change");
  if (!uri || std::string(uri).find("risk-level-change") == std::string::npos) {
    std::cout << "FAIL risk_level_change\n";
    return 1;
  }
  std::cout << "ok\n";
  return 0;
}
