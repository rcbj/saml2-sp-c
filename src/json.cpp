// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <sstream>

namespace iya::saml {
namespace {

class Parser {
 public:
  explicit Parser(const std::string& text) : text_(text) {}

  Json parse() {
    skip();
    Json value = parse_value();
    skip();
    if (i_ != text_.size()) throw Failure("config", "the configuration cannot be read as JSON: trailing data");
    return value;
  }

 private:
  const std::string& text_;
  size_t i_ = 0;

  void skip() {
    while (i_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[i_]))) i_++;
  }

  char peek() const { return i_ < text_.size() ? text_[i_] : '\0'; }

  char get() {
    if (i_ >= text_.size()) throw Failure("config", "the configuration cannot be read as JSON: unexpected end");
    return text_[i_++];
  }

  Json parse_value() {
    skip();
    char c = peek();
    if (c == '{') return parse_object();
    if (c == '[') return parse_array();
    if (c == '"') {
      Json out;
      out.type = Json::Type::String;
      out.text = parse_string();
      return out;
    }
    if (c == 't' || c == 'f') return parse_bool();
    if (c == 'n') return parse_null();
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parse_number();
    throw Failure("config", "the configuration cannot be read as JSON: unexpected character");
  }

  Json parse_object() {
    get();
    Json out;
    out.type = Json::Type::Object;
    skip();
    if (peek() == '}') {
      get();
      return out;
    }
    while (true) {
      skip();
      if (peek() != '"') throw Failure("config", "the configuration cannot be read as JSON: object key");
      std::string key = parse_string();
      skip();
      if (get() != ':') throw Failure("config", "the configuration cannot be read as JSON: expected colon");
      Json value = parse_value();
      bool replaced = false;
      for (auto& field : out.fields) {
        if (field.first == key) {
          field.second = std::move(value);
          replaced = true;
          break;
        }
      }
      if (!replaced) out.fields.emplace_back(std::move(key), std::move(value));
      skip();
      char c = get();
      if (c == '}') break;
      if (c != ',') throw Failure("config", "the configuration cannot be read as JSON: expected comma");
    }
    return out;
  }

  Json parse_array() {
    get();
    Json out;
    out.type = Json::Type::Array;
    skip();
    if (peek() == ']') {
      get();
      return out;
    }
    while (true) {
      out.items.push_back(parse_value());
      skip();
      char c = get();
      if (c == ']') break;
      if (c != ',') throw Failure("config", "the configuration cannot be read as JSON: expected comma");
    }
    return out;
  }

  std::string parse_string() {
    if (get() != '"') throw Failure("config", "the configuration cannot be read as JSON: string");
    std::string out;
    while (true) {
      if (i_ >= text_.size()) throw Failure("config", "the configuration cannot be read as JSON: unterminated string");
      char c = get();
      if (c == '"') break;
      if (c == '\\') {
        if (i_ >= text_.size()) throw Failure("config", "the configuration cannot be read as JSON: bad escape");
        char e = get();
        switch (e) {
          case '"':
          case '\\':
          case '/':
            out.push_back(e);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            unsigned code = 0;
            for (int n = 0; n < 4; n++) {
              if (i_ >= text_.size()) throw Failure("config", "the configuration cannot be read as JSON: bad escape");
              char h = get();
              code <<= 4;
              if (h >= '0' && h <= '9') code |= h - '0';
              else if (h >= 'a' && h <= 'f') code |= h - 'a' + 10;
              else if (h >= 'A' && h <= 'F') code |= h - 'A' + 10;
              else throw Failure("config", "the configuration cannot be read as JSON: bad escape");
            }
            append_utf8(out, code);
            break;
          }
          default:
            throw Failure("config", "the configuration cannot be read as JSON: bad escape");
        }
      } else {
        out.push_back(c);
      }
    }
    return out;
  }

  static void append_utf8(std::string& out, unsigned code) {
    if (code < 0x80) {
      out.push_back(static_cast<char>(code));
    } else if (code < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (code >> 6)));
      out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xE0 | (code >> 12)));
      out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
    }
  }

  Json parse_bool() {
    Json out;
    out.type = Json::Type::Bool;
    if (text_.compare(i_, 4, "true") == 0) {
      i_ += 4;
      out.b = true;
      return out;
    }
    if (text_.compare(i_, 5, "false") == 0) {
      i_ += 5;
      out.b = false;
      return out;
    }
    throw Failure("config", "the configuration cannot be read as JSON: bad literal");
  }

  Json parse_null() {
    if (text_.compare(i_, 4, "null") != 0) throw Failure("config", "the configuration cannot be read as JSON: bad literal");
    i_ += 4;
    Json out;
    out.type = Json::Type::Null;
    return out;
  }

  Json parse_number() {
    size_t start = i_;
    if (peek() == '-') get();
    if (!std::isdigit(static_cast<unsigned char>(peek()))) throw Failure("config", "the configuration cannot be read as JSON: bad number");
    if (peek() == '0') {
      get();
    } else {
      while (std::isdigit(static_cast<unsigned char>(peek()))) get();
    }
    if (peek() == '.') {
      get();
      if (!std::isdigit(static_cast<unsigned char>(peek()))) throw Failure("config", "the configuration cannot be read as JSON: bad number");
      while (std::isdigit(static_cast<unsigned char>(peek()))) get();
    }
    if (peek() == 'e' || peek() == 'E') {
      get();
      if (peek() == '+' || peek() == '-') get();
      if (!std::isdigit(static_cast<unsigned char>(peek()))) throw Failure("config", "the configuration cannot be read as JSON: bad number");
      while (std::isdigit(static_cast<unsigned char>(peek()))) get();
    }
    Json out;
    out.type = Json::Type::Number;
    out.text = text_.substr(start, i_ - start);
    out.num = std::strtod(out.text.c_str(), nullptr);
    return out;
  }
};

void dump_string(std::string& out, const std::string& value) {
  out.push_back('"');
  for (unsigned char c : value) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
}

void dump_into(std::string& out, const Json& value) {
  switch (value.type) {
    case Json::Type::Null:
      out += "null";
      break;
    case Json::Type::Bool:
      out += value.b ? "true" : "false";
      break;
    case Json::Type::Number:
      if (!value.text.empty()) {
        out += value.text;
      } else if (std::isfinite(value.num) && value.num == std::floor(value.num) && std::fabs(value.num) < 1e15) {
        out += std::to_string(static_cast<long long>(value.num));
      } else {
        std::ostringstream stream;
        stream.setf(std::ios::fmtflags(0), std::ios::floatfield);
        stream << value.num;
        out += stream.str();
      }
      break;
    case Json::Type::String:
      dump_string(out, value.text);
      break;
    case Json::Type::Array:
      out.push_back('[');
      for (size_t i = 0; i < value.items.size(); i++) {
        if (i) out.push_back(',');
        dump_into(out, value.items[i]);
      }
      out.push_back(']');
      break;
    case Json::Type::Object:
      out.push_back('{');
      for (size_t i = 0; i < value.fields.size(); i++) {
        if (i) out.push_back(',');
        dump_string(out, value.fields[i].first);
        out.push_back(':');
        dump_into(out, value.fields[i].second);
      }
      out.push_back('}');
      break;
  }
}

}  // namespace

const Json* Json::find(const std::string& key) const {
  const Json* found = nullptr;
  for (const auto& field : fields) {
    if (field.first == key) found = &field.second;
  }
  return found;
}

bool Json::has(const std::string& key) const { return find(key) != nullptr; }

std::string Json::str_or(const std::string& key) const {
  const Json* value = find(key);
  if (!value || value->type != Type::String) return "";
  return value->text;
}

Json parse_json(const std::string& text) { return Parser(text).parse(); }

std::string json_dump(const Json& value) {
  std::string out;
  dump_into(out, value);
  return out;
}

std::string lower_copy(std::string value) {
  for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}

std::string trim_copy(const std::string& value) {
  size_t begin = 0;
  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) begin++;
  size_t end = value.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) end--;
  return value.substr(begin, end - begin);
}

bool starts_with(const std::string& value, const std::string& prefix) { return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0; }

bool ends_with(const std::string& value, const std::string& suffix) {
  return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string join_strings(const std::vector<std::string>& parts, const std::string& sep) {
  std::string out;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i) out += sep;
    out += parts[i];
  }
  return out;
}

}  // namespace iya::saml
