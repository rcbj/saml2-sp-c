// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <sys/stat.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

const char* kUsage =
    "Usage:\n"
    "  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n"
    "  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n"
    "      A new RSA key and a self-signed certificate, written where the configuration's privateKey and\n"
    "      certificate point (or to --key and --cert). Refuses to replace existing files without --force.\n"
    "      The common name defaults to the host of the configuration's entityId.\n"
    "\n"
    "  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]\n"
    "      This service provider's SAML metadata, from the configuration and its certificate. Written to\n"
    "      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run.\n"
    "\n"
    "  saml2-sp summarize-idp\n"
    "      Read identity-provider metadata on standard input. Write its entityID, its SSO URL, and one\n"
    "      artifact-resolution URL per line.";

struct Args {
  std::string command;
  std::map<std::string, std::string> values;
};

Args parse_args(int argc, char** argv) {
  Args out;
  int index = 1;
  if (argc > 1) {
    out.command = argv[1];
    index = 2;
  }
  for (; index < argc; index++) {
    std::string item = argv[index];
    if (item.rfind("--", 0) != 0) throw std::runtime_error("unexpected argument " + item + "\n\n" + kUsage);
    std::string key = item.substr(2);
    if (key == "force" || key == "help") {
      out.values[key] = "true";
      continue;
    }
    if (index + 1 >= argc || std::string(argv[index + 1]).rfind("--", 0) == 0) throw std::runtime_error("--" + key + " needs a value\n\n" + kUsage);
    index++;
    out.values[key] = argv[index];
  }
  return out;
}

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error(path + ": " + std::strerror(errno));
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

void write_mode(const fs::path& path, const std::string& text, mode_t mode) {
  if (path.has_parent_path() && path.parent_path() != "" && path.parent_path() != ".") fs::create_directories(path.parent_path());
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error(path.string() + ": " + std::strerror(errno));
    out << text;
  }
  if (chmod(path.c_str(), mode) != 0) throw std::runtime_error(path.string() + ": " + std::strerror(errno));
}

bool exists(const fs::path& path) {
  std::error_code error;
  return fs::exists(path, error);
}

std::string host_of(const std::string& entity) {
  std::string rest = entity;
  auto scheme = rest.find("://");
  if (scheme != std::string::npos) rest = rest.substr(scheme + 3);
  auto slash = rest.find('/');
  if (slash != std::string::npos) rest = rest.substr(0, slash);
  if (rest.empty()) return entity;
  if (rest.front() == '[') {
    auto end = rest.find(']');
    if (end != std::string::npos) return rest.substr(1, end - 1);
  }
  auto colon = rest.rfind(':');
  if (colon != std::string::npos && rest.find(':') == colon) return rest.substr(0, colon);
  return rest;
}

std::string config_path_of(const iya::saml::Json& object, const std::string& config_path, const std::string& key) {
  const iya::saml::Json* value = object.find(key);
  if (!value || value->type != iya::saml::Json::Type::String || value->text.empty() || value->text.find("-----BEGIN ") != std::string::npos ||
      value->text.rfind("env:", 0) == 0) {
    throw std::runtime_error(config_path + "'s " + key + " must be a file path for generate-keys to write to");
  }
  std::string text = value->text;
  if (text.rfind("file:", 0) == 0) text = text.substr(5);
  fs::path path(text);
  if (path.is_relative()) path = fs::absolute(config_path).parent_path() / path;
  return fs::absolute(path).lexically_normal().string();
}

int generate_keys(const Args& args) {
  std::string key = args.values.count("key") ? args.values.at("key") : "";
  std::string cert = args.values.count("cert") ? args.values.at("cert") : "";
  std::string cn = args.values.count("cn") ? args.values.at("cn") : "";
  if (args.values.count("config")) {
    const std::string& config_path = args.values.at("config");
    iya::saml::Json parsed = iya::saml::parse_json(read_file(config_path));
    if (parsed.type != iya::saml::Json::Type::Object) throw std::runtime_error(config_path + " is not a JSON object");
    if (key.empty()) key = config_path_of(parsed, config_path, "privateKey");
    if (cert.empty()) cert = config_path_of(parsed, config_path, "certificate");
    if (cn.empty()) {
      std::string entity = parsed.str_or("entityId");
      cn = entity.empty() ? "" : host_of(entity);
    }
  }
  if (key.empty() || cert.empty()) throw std::runtime_error(std::string("generate-keys needs --config, or --key and --cert\n\n") + kUsage);
  if (cn.empty()) cn = "saml2-sp service provider";
  key = fs::absolute(key).string();
  cert = fs::absolute(cert).string();
  if (!args.values.count("force") && (exists(key) || exists(cert))) {
    std::string which = exists(key) ? key : cert;
    throw std::runtime_error(which + " already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before the next sign-in.");
  }
  int days = 1095;
  if (args.values.count("days") && !args.values.at("days").empty()) {
    try {
      size_t used = 0;
      days = std::stoi(args.values.at("days"), &used);
      if (used != args.values.at("days").size() || days <= 0) throw std::runtime_error("");
    } catch (...) {
      throw std::runtime_error("--days must be a positive whole number");
    }
  }
  int bits = 3072;
  if (args.values.count("bits") && !args.values.at("bits").empty()) {
    try {
      size_t used = 0;
      bits = std::stoi(args.values.at("bits"), &used);
      if (used != args.values.at("bits").size() || (bits != 2048 && bits != 3072 && bits != 4096)) throw std::runtime_error("");
    } catch (const std::runtime_error& ex) {
      if (std::string(ex.what()).find("--days") != std::string::npos) throw;
      throw std::runtime_error("--bits must be 2048, 3072 or 4096");
    } catch (...) {
      throw std::runtime_error("--bits must be 2048, 3072 or 4096");
    }
  }
  iya::saml::KeyPair pair = iya::saml::create_key_pair(cn, days, bits);
  write_mode(key, pair.private_key_pem, 0600);
  write_mode(cert, pair.certificate_pem, 0644);
  std::printf("Wrote the private key  %s (mode 600)\n", key.c_str());
  std::printf("Wrote the certificate  %s\n", cert.c_str());
  std::printf("  subject   CN=%s\n", cn.c_str());
  std::printf("  valid to  %s\n", pair.valid_to.c_str());
  std::printf("  sha256    %s\n", pair.fingerprint_sha256.c_str());
  return 0;
}

int write_metadata(const Args& args) {
  if (!args.values.count("config") || args.values.at("config").empty()) throw std::runtime_error(std::string("metadata needs --config\n\n") + kUsage);
  std::string entity = args.values.count("entity-id") ? args.values.at("entity-id") : "";
  std::string acs = args.values.count("acs-url") ? args.values.at("acs-url") : "";
  std::string xml = iya::saml::metadata_for_config(args.values.at("config"), entity, acs);
  if (args.values.count("out") && !args.values.at("out").empty()) {
    fs::path target = fs::absolute(args.values.at("out"));
    write_mode(target, xml, 0644);
    std::printf("Wrote the service provider metadata to %s\n", target.string().c_str());
    return 0;
  }
  std::cout << xml;
  return 0;
}

int summarize() {
  std::string raw;
  char buffer[4096];
  while (std::cin) {
    std::cin.read(buffer, sizeof buffer);
    raw.append(buffer, static_cast<size_t>(std::cin.gcount()));
    if (raw.size() > (2u << 20)) break;
  }
  if (raw.size() > (2u << 20)) raw.resize(2u << 20);
  iya::saml::IdpDescription meta = iya::saml::describe_idp(raw);
  std::cout << meta.entity_id << "\n" << meta.sso << "\n";
  for (const std::string& service : meta.artifact_services) std::cout << service << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    Args args = parse_args(argc, argv);
    if (args.command.empty() || args.values.count("help") || args.command == "help") {
      std::cout << kUsage << "\n";
      return 0;
    }
    if (args.command == "generate-keys") return generate_keys(args);
    if (args.command == "metadata") return write_metadata(args);
    if (args.command == "summarize-idp") return summarize();
    throw std::runtime_error("unknown command " + args.command + "\n\n" + kUsage);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << "\n";
    return 1;
  }
}
