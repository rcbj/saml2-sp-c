// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "internal.hpp"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <cctype>
#include <set>

namespace iya::saml {
namespace {

struct XmlReady {
  XmlReady() { xmlInitParser(); }
};

XmlReady xml_ready;

xmlParserInputPtr refuse_entity(void* /*ctx*/, const xmlChar* /*publicId*/, const xmlChar* /*systemId*/) { return nullptr; }

bool contains_doctype(const std::string& text) {
  std::string lower;
  lower.reserve(text.size());
  for (unsigned char c : text) lower.push_back(static_cast<char>(std::tolower(c)));
  return lower.find("<!doctype") != std::string::npos || lower.find("<!entity") != std::string::npos;
}

std::string local_name(xmlNodePtr node) {
  if (!node || !node->name) return "";
  return reinterpret_cast<const char*>(node->name);
}

std::string ns_href(xmlNodePtr node) {
  if (!node || !node->ns || !node->ns->href) return "";
  return reinterpret_cast<const char*>(node->ns->href);
}

std::string prefix_key(xmlNsPtr ns) {
  if (!ns || !ns->prefix) return "";
  return reinterpret_cast<const char*>(ns->prefix);
}

std::string c14n_copy(xmlNodePtr node, int mode, int comments, const std::vector<std::string>& prefixes) {
  xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
  if (!doc) throw Failure("signature", "the signature does not verify");
  xmlNodePtr copy = xmlDocCopyNode(node, doc, 1);
  if (!copy) {
    xmlFreeDoc(doc);
    throw Failure("signature", "the signature does not verify");
  }
  xmlDocSetRootElement(doc, copy);
  std::set<std::string> seen;
  for (xmlNsPtr ns = copy->nsDef; ns; ns = ns->next) seen.insert(prefix_key(ns));
  for (xmlNodePtr parent = node->parent; parent && parent->type == XML_ELEMENT_NODE; parent = parent->parent) {
    for (xmlNsPtr ns = parent->nsDef; ns; ns = ns->next) {
      std::string key = prefix_key(ns);
      if (!seen.insert(key).second) continue;
      xmlNewNs(copy, ns->href, ns->prefix);
    }
  }
  std::vector<const xmlChar*> list;
  std::vector<xmlChar*> owned;
  xmlChar** inclusive = nullptr;
  if (!prefixes.empty()) {
    for (const std::string& prefix : prefixes) {
      owned.push_back(xmlStrdup(BAD_CAST prefix.c_str()));
      list.push_back(owned.back());
    }
    list.push_back(nullptr);
    inclusive = const_cast<xmlChar**>(list.data());
  }
  xmlBufferPtr buffer = xmlBufferCreate();
  xmlOutputBufferPtr out = xmlOutputBufferCreateBuffer(buffer, nullptr);
  int rc = -1;
  if (out) rc = xmlC14NDocSaveTo(doc, nullptr, mode, inclusive, comments, out);
  if (out) xmlOutputBufferClose(out);
  std::string result;
  if (rc >= 0 && buffer && xmlBufferContent(buffer)) result.assign(reinterpret_cast<const char*>(xmlBufferContent(buffer)), xmlBufferLength(buffer));
  if (buffer) xmlBufferFree(buffer);
  for (xmlChar* item : owned) xmlFree(item);
  xmlFreeDoc(doc);
  if (rc < 0) throw Failure("signature", "the signature does not verify");
  return result;
}

int c14n_mode(const std::string& algorithm, int& comments) {
  comments = 0;
  if (algorithm == kExcC14N) return XML_C14N_EXCLUSIVE_1_0;
  if (algorithm == kExcC14NComments) {
    comments = 1;
    return XML_C14N_EXCLUSIVE_1_0;
  }
  if (algorithm == kC14N10) return XML_C14N_1_0;
  if (algorithm == kC14N10Comments) {
    comments = 1;
    return XML_C14N_1_0;
  }
  return -1;
}

std::string canonicalize(xmlNodePtr node, const std::string& algorithm, const std::string& prefix_list) {
  int comments = 0;
  int mode = c14n_mode(algorithm, comments);
  if (mode < 0) throw Failure("signature", "the signature uses the canonicalization " + (algorithm.empty() ? "(none)" : algorithm) + ", which is refused");
  std::vector<std::string> prefixes;
  std::string current;
  for (size_t i = 0; i <= prefix_list.size(); i++) {
    if (i == prefix_list.size() || std::isspace(static_cast<unsigned char>(prefix_list[i]))) {
      if (!current.empty()) prefixes.push_back(current);
      current.clear();
    } else {
      current.push_back(prefix_list[i]);
    }
  }
  return c14n_copy(node, mode, comments, prefixes);
}

std::string inclusive_prefixes(xmlNodePtr transform) {
  if (!transform) return "";
  for (xmlNodePtr c = transform->children; c; c = c->next) {
    if (c->type == XML_ELEMENT_NODE && local_name(c) == "InclusiveNamespaces") return attr_of(c, "PrefixList");
  }
  return "";
}

std::string algorithm_of(xmlNodePtr parent, const char* local) {
  xmlNodePtr found = one_child(parent, kNsDsig, local);
  if (!found) return "";
  return attr_of(found, "Algorithm");
}

std::string compact_text(xmlNodePtr el) {
  std::string text = trim_copy(iter_text(el));
  std::string out;
  for (char c : text) {
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') out.push_back(c);
  }
  return out;
}

const EVP_MD* hash_for_sig(const std::string& alg) {
  if (alg == kRsaSha256) return EVP_sha256();
  if (alg == kRsaSha384) return EVP_sha384();
  if (alg == kRsaSha512) return EVP_sha512();
  return nullptr;
}

const EVP_MD* hash_for_digest(const std::string& alg) {
  if (alg == kDigest256) return EVP_sha256();
  if (alg == kDigest384) return EVP_sha384();
  if (alg == kDigest512) return EVP_sha512();
  return nullptr;
}

std::string digest_raw(const EVP_MD* md, const std::string& data) {
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), out, &len, md, nullptr);
  return std::string(reinterpret_cast<char*>(out), len);
}

bool bytes_equal(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char v = 0;
  for (size_t i = 0; i < a.size(); i++) v |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  return v == 0;
}

void write_escaped(std::string& out, const xmlChar* text) {
  if (!text) return;
  out += escape_xml(reinterpret_cast<const char*>(text));
}

void write_node(xmlNodePtr node, std::string& out) {
  if (!node) return;
  if (node->type == XML_TEXT_NODE || node->type == XML_CDATA_SECTION_NODE) {
    write_escaped(out, node->content);
    return;
  }
  if (node->type != XML_ELEMENT_NODE) return;
  out.push_back('<');
  if (node->ns && node->ns->prefix) {
    out += reinterpret_cast<const char*>(node->ns->prefix);
    out.push_back(':');
  }
  out += local_name(node);
  for (xmlNsPtr ns = node->nsDef; ns; ns = ns->next) {
    out += " xmlns";
    if (ns->prefix) {
      out.push_back(':');
      out += reinterpret_cast<const char*>(ns->prefix);
    }
    out += "=\"";
    write_escaped(out, ns->href);
    out.push_back('"');
  }
  for (xmlAttrPtr attr = node->properties; attr; attr = attr->next) {
    out.push_back(' ');
    if (attr->ns && attr->ns->prefix) {
      out += reinterpret_cast<const char*>(attr->ns->prefix);
      out.push_back(':');
    }
    out += reinterpret_cast<const char*>(attr->name);
    out += "=\"";
    xmlChar* value = xmlNodeListGetString(node->doc, attr->children, 1);
    write_escaped(out, value);
    if (value) xmlFree(value);
    out.push_back('"');
  }
  if (!node->children) {
    out += "/>";
    return;
  }
  out.push_back('>');
  for (xmlNodePtr c = node->children; c; c = c->next) write_node(c, out);
  out += "</";
  if (node->ns && node->ns->prefix) {
    out += reinterpret_cast<const char*>(node->ns->prefix);
    out.push_back(':');
  }
  out += local_name(node);
  out.push_back('>');
}

xmlNodePtr remove_enveloped(xmlNodePtr node, xmlNodePtr signature) {
  xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
  xmlNodePtr copy = xmlDocCopyNode(node, doc, 1);
  xmlDocSetRootElement(doc, copy);
  std::string original;
  auto values = child_elements(signature, kNsDsig, "SignatureValue");
  if (!values.empty()) original = compact_text(values[0]);
  xmlNodePtr removed = nullptr;
  for (xmlNodePtr c = copy->children; c; c = c->next) {
    if (!same_element(c, kNsDsig, "Signature")) continue;
    std::string value;
    auto inner = child_elements(c, kNsDsig, "SignatureValue");
    if (!inner.empty()) value = compact_text(inner[0]);
    if (value == original || c->parent == copy) {
      removed = c;
      break;
    }
  }
  if (removed) xmlUnlinkNode(removed), xmlFreeNode(removed);
  return copy;
}

std::string apply_transforms(xmlNodePtr element, xmlNodePtr signature, const std::vector<xmlNodePtr>& transforms) {
  xmlNodePtr node = element;
  XmlDoc owned;
  std::string data;
  bool have_data = false;
  if (transforms.empty()) return canonicalize(element, kC14N10, "");
  for (size_t index = 0; index < transforms.size(); index++) {
    std::string alg = attr_of(transforms[index], "Algorithm");
    if (have_data) {
      owned = parse_xml(data, "the transformed reference");
      node = owned.root();
      have_data = false;
    }
    if (alg == kEnveloped) {
      xmlNodePtr copy = remove_enveloped(node, signature);
      if (owned.doc && node != element) {
        // drop the previous owned document after the copy is independent
      }
      if (owned.doc) {
        xmlFreeDoc(owned.doc);
        owned.doc = nullptr;
      }
      owned.doc = copy->doc;
      node = copy;
      continue;
    }
    int comments = 0;
    if (c14n_mode(alg, comments) < 0) throw Failure("signature", "the signature uses the transform " + (alg.empty() ? "(none)" : alg) + ", which is refused");
    data = canonicalize(node, alg, inclusive_prefixes(transforms[index]));
    have_data = true;
    node = nullptr;
    if (index + 1 == transforms.size()) return data;
  }
  if (have_data) return data;
  return canonicalize(node, kC14N10, "");
}

xmlNsPtr ds_ns(xmlNodePtr node) {
  xmlNsPtr ns = xmlNewNs(node, BAD_CAST kNsDsig, BAD_CAST "ds");
  xmlSetNs(node, ns);
  return ns;
}

}  // namespace

std::string escape_xml(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&apos;";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

XmlDoc parse_xml(const std::string& text, const std::string& what) {
  if (contains_doctype(text)) throw Failure("xml", what + " carries a DOCTYPE or an entity declaration, which SAML never needs");
  xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
  if (!ctxt) throw Failure("xml", what + " is not well-formed XML: parser");
  if (ctxt->sax) {
    ctxt->sax->resolveEntity = refuse_entity;
    ctxt->sax->getEntity = nullptr;
    ctxt->sax->externalSubset = nullptr;
  }
  xmlDocPtr doc = xmlCtxtReadMemory(ctxt, text.data(), static_cast<int>(text.size()), "saml.xml", nullptr, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOCDATA);
  std::string message = "parse error";
  xmlErrorPtr err = xmlCtxtGetLastError(ctxt);
  if (err && err->message) {
    message = err->message;
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) message.pop_back();
  }
  xmlFreeParserCtxt(ctxt);
  if (!doc) throw Failure("xml", what + " is not well-formed XML: " + message);
  if (!xmlDocGetRootElement(doc)) {
    xmlFreeDoc(doc);
    throw Failure("xml", what + " is not well-formed XML: no document element");
  }
  return XmlDoc(doc);
}

std::string serialize_xml(xmlNodePtr node) {
  xmlNodePtr root = node;
  while (root && root->parent && root->parent->type == XML_ELEMENT_NODE) root = root->parent;
  std::string out;
  write_node(root, out);
  return out;
}

bool same_element(xmlNodePtr el, const char* ns, const char* local) { return el && el->type == XML_ELEMENT_NODE && local_name(el) == local && ns_href(el) == ns; }

std::vector<xmlNodePtr> child_elements(xmlNodePtr el, const char* ns, const char* local) {
  std::vector<xmlNodePtr> out;
  if (!el) return out;
  for (xmlNodePtr c = el->children; c; c = c->next) {
    if (same_element(c, ns, local)) out.push_back(c);
  }
  return out;
}

xmlNodePtr one_child(xmlNodePtr el, const char* ns, const char* local) {
  auto found = child_elements(el, ns, local);
  if (found.size() > 1) throw Failure("validation", "<" + local_name(el) + "> has more than one <" + local + ">");
  if (found.empty()) return nullptr;
  return found[0];
}

std::vector<xmlNodePtr> descendant_elements(xmlNodePtr el, const char* ns, const char* local) {
  std::vector<xmlNodePtr> out;
  if (!el) return out;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr n) {
    for (xmlNodePtr c = n->children; c; c = c->next) {
      if (c->type != XML_ELEMENT_NODE) continue;
      if (same_element(c, ns, local)) out.push_back(c);
      walk(c);
    }
  };
  walk(el);
  return out;
}

std::string iter_text(xmlNodePtr el) {
  if (!el) return "";
  std::string out;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr n) {
    for (xmlNodePtr c = n->children; c; c = c->next) {
      if (c->type == XML_TEXT_NODE || c->type == XML_CDATA_SECTION_NODE) {
        if (c->content) out += reinterpret_cast<const char*>(c->content);
      } else if (c->type == XML_ELEMENT_NODE) {
        walk(c);
      }
    }
  };
  walk(el);
  return out;
}

std::string text_of(xmlNodePtr el) { return trim_copy(iter_text(el)); }

std::string attr_of(xmlNodePtr el, const char* name) {
  if (!el) return "";
  xmlChar* value = xmlGetProp(el, BAD_CAST name);
  if (!value) return "";
  std::string out(reinterpret_cast<const char*>(value));
  xmlFree(value);
  return out;
}

bool has_attr(xmlNodePtr el, const char* name) {
  if (!el) return false;
  xmlAttrPtr attr = xmlHasProp(el, BAD_CAST name);
  return attr != nullptr;
}

void assert_unique_ids(xmlNodePtr root) {
  if (!root) return;
  std::set<std::string> seen;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr n) {
    if (!n || n->type != XML_ELEMENT_NODE) return;
    for (const char* name : {"ID", "Id", "id"}) {
      if (!has_attr(n, name)) continue;
      std::string value = attr_of(n, name);
      if (value.empty()) continue;
      if (!seen.insert(value).second) throw Failure("signature", "two elements carry the ID " + value);
    }
    for (xmlNodePtr c = n->children; c; c = c->next) walk(c);
  };
  walk(root);
}

xmlNodePtr element_by_id(xmlNodePtr root, const std::string& id) {
  xmlNodePtr found = nullptr;
  std::function<void(xmlNodePtr)> walk = [&](xmlNodePtr n) {
    if (!n || found) return;
    if (n->type == XML_ELEMENT_NODE) {
      for (const char* name : {"ID", "Id", "id"}) {
        if (has_attr(n, name) && attr_of(n, name) == id) {
          found = n;
          return;
        }
      }
    }
    for (xmlNodePtr c = n->children; c; c = c->next) walk(c);
  };
  walk(root);
  return found;
}

std::string pem_body(const std::string& pem) {
  std::string out;
  std::string line;
  for (size_t i = 0; i <= pem.size(); i++) {
    if (i == pem.size() || pem[i] == '\n' || pem[i] == '\r') {
      std::string trimmed = trim_copy(line);
      if (!trimmed.empty() && !starts_with(trimmed, "-----")) out += trimmed;
      line.clear();
    } else {
      line.push_back(pem[i]);
    }
  }
  return out;
}

std::string to_pem_cert(const std::string& b64) {
  std::string compact;
  for (char c : b64) {
    if (!std::isspace(static_cast<unsigned char>(c))) compact.push_back(c);
  }
  std::string out = "-----BEGIN CERTIFICATE-----\n";
  for (size_t i = 0; i < compact.size(); i += 64) out += compact.substr(i, 64) + "\n";
  out += "-----END CERTIFICATE-----\n";
  return out;
}

std::string verify_signed(xmlNodePtr element, const std::vector<X509*>& certs, const std::string& what) {
  xmlNodePtr sig = one_child(element, kNsDsig, "Signature");
  if (!sig) return "";
  std::string element_id = attr_of(element, "ID");
  if (element_id.empty()) throw Failure("signature", what + " is signed but has no ID for the signature to refer to");
  xmlNodePtr signed_info = one_child(sig, kNsDsig, "SignedInfo");
  if (!signed_info) throw Failure("signature", what + "'s signature has no SignedInfo");
  std::string c14n_alg = algorithm_of(signed_info, "CanonicalizationMethod");
  if (c14n_alg != kExcC14N && c14n_alg != kExcC14NComments && c14n_alg != kC14N10 && c14n_alg != kC14N10Comments) {
    throw Failure("signature", what + "'s signature uses the canonicalization " + (c14n_alg.empty() ? "(none)" : c14n_alg) + ", which is refused");
  }
  std::string sig_alg = algorithm_of(signed_info, "SignatureMethod");
  const EVP_MD* sig_md = hash_for_sig(sig_alg);
  if (!sig_md) throw Failure("signature", what + "'s signature uses " + (sig_alg.empty() ? "(none)" : sig_alg) + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
  auto refs = child_elements(signed_info, kNsDsig, "Reference");
  if (refs.size() != 1) throw Failure("signature", what + "'s signature has " + std::to_string(refs.size()) + " references; exactly one is accepted");
  xmlNodePtr ref = refs[0];
  std::string uri = attr_of(ref, "URI");
  if (uri != "#" + element_id) {
    throw Failure("signature", what + "'s signature refers to " + (uri.empty() ? "(nothing)" : uri) + ", not to " + what + " itself (#" + element_id + ")");
  }
  std::string digest_alg = algorithm_of(ref, "DigestMethod");
  const EVP_MD* digest_md = hash_for_digest(digest_alg);
  if (!digest_md) throw Failure("signature", what + "'s signature digests with " + (digest_alg.empty() ? "(none)" : digest_alg) + ", which is refused");
  std::vector<xmlNodePtr> transforms;
  xmlNodePtr transforms_el = one_child(ref, kNsDsig, "Transforms");
  if (transforms_el) transforms = child_elements(transforms_el, kNsDsig, "Transform");
  for (xmlNodePtr transform : transforms) {
    std::string alg = attr_of(transform, "Algorithm");
    if (alg != kEnveloped && alg != kExcC14N && alg != kExcC14NComments && alg != kC14N10 && alg != kC14N10Comments) {
      throw Failure("signature", what + "'s signature uses the transform " + (alg.empty() ? "(none)" : alg) + ", which is refused");
    }
  }
  if (certs.empty()) throw Failure("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
  std::string reference;
  try {
    reference = apply_transforms(element, sig, transforms);
  } catch (const Failure& failure) {
    if (failure.kind == "signature" && failure.what() == std::string("the signature does not verify")) {
      throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
    }
    if (failure.kind == "xml" || failure.kind == "validation" || (failure.kind == "signature" && std::string(failure.what()).find("which is refused") != std::string::npos)) throw;
    throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
  }
  xmlNodePtr digest_value = one_child(ref, kNsDsig, "DigestValue");
  std::string got;
  try {
    got = b64_decode(compact_text(digest_value));
  } catch (...) {
    throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the digest is not base64");
  }
  std::string want = digest_raw(digest_md, reference);
  if (!bytes_equal(got, want)) throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
  std::string info_prefixes;
  xmlNodePtr method = one_child(signed_info, kNsDsig, "CanonicalizationMethod");
  if (method) info_prefixes = inclusive_prefixes(method);
  std::string signed_bytes;
  try {
    signed_bytes = canonicalize(signed_info, c14n_alg, info_prefixes);
  } catch (...) {
    throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
  }
  xmlNodePtr signature_value = one_child(sig, kNsDsig, "SignatureValue");
  std::string sig_bytes;
  try {
    sig_bytes = b64_decode(compact_text(signature_value));
  } catch (...) {
    throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature value is not base64");
  }
  std::string hashed = digest_raw(sig_md, signed_bytes);
  bool verified = false;
  for (X509* cert : certs) {
    OwnedKey pub(X509_get_pubkey(cert));
    if (!pub.key || EVP_PKEY_get_id(pub.key) != EVP_PKEY_RSA) continue;
    if (rsa_verify_pkcs1(pub.key, signed_bytes, sig_bytes, sig_md)) {
      verified = true;
      break;
    }
  }
  if (!verified) throw Failure("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
  xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
  xmlNodePtr copy = xmlDocCopyNode(element, doc, 1);
  xmlDocSetRootElement(doc, copy);
  std::set<std::string> seen;
  for (xmlNsPtr ns = copy->nsDef; ns; ns = ns->next) seen.insert(prefix_key(ns));
  for (xmlNodePtr parent = element->parent; parent && parent->type == XML_ELEMENT_NODE; parent = parent->parent) {
    for (xmlNsPtr ns = parent->nsDef; ns; ns = ns->next) {
      if (seen.insert(prefix_key(ns)).second) xmlNewNs(copy, ns->href, ns->prefix);
    }
  }
  for (xmlNodePtr c = copy->children; c;) {
    xmlNodePtr next = c->next;
    if (same_element(c, kNsDsig, "Signature")) {
      xmlUnlinkNode(c);
      xmlFreeNode(c);
    }
    c = next;
  }
  std::string canonical = c14n_copy(copy, XML_C14N_EXCLUSIVE_1_0, 0, {});
  xmlFreeDoc(doc);
  return canonical;
}

std::string sign_enveloped(const std::string& xml, const std::string& element_id, EVP_PKEY* key, X509* cert) {
  XmlDoc doc = parse_xml(xml, "the message to sign");
  xmlNodePtr target = element_by_id(doc.root(), element_id);
  if (!target) throw Failure("signature", "no element has ID " + element_id);
  std::string reference = canonicalize(target, kExcC14N, "");
  std::string digest = b64_encode(digest_raw(EVP_sha256(), reference));
  xmlNodePtr signature = xmlNewNode(nullptr, BAD_CAST "Signature");
  xmlNsPtr ds = xmlNewNs(signature, BAD_CAST kNsDsig, BAD_CAST "ds");
  xmlSetNs(signature, ds);
  xmlNodePtr issuer = nullptr;
  for (xmlNodePtr c = target->children; c; c = c->next) {
    if (same_element(c, kNsSaml, "Issuer")) {
      issuer = c;
      break;
    }
  }
  if (issuer) xmlAddNextSibling(issuer, signature);
  else if (target->children) xmlAddPrevSibling(target->children, signature);
  else xmlAddChild(target, signature);
  xmlNodePtr signed_info = xmlNewChild(signature, ds, BAD_CAST "SignedInfo", nullptr);
  xmlNewNs(signed_info, BAD_CAST kNsDsig, BAD_CAST "ds");
  xmlNodePtr c14n = xmlNewChild(signed_info, ds, BAD_CAST "CanonicalizationMethod", nullptr);
  xmlNewProp(c14n, BAD_CAST "Algorithm", BAD_CAST kExcC14N);
  xmlNodePtr method = xmlNewChild(signed_info, ds, BAD_CAST "SignatureMethod", nullptr);
  xmlNewProp(method, BAD_CAST "Algorithm", BAD_CAST kRsaSha256);
  xmlNodePtr ref = xmlNewChild(signed_info, ds, BAD_CAST "Reference", nullptr);
  xmlNewProp(ref, BAD_CAST "URI", BAD_CAST ("#" + element_id).c_str());
  xmlNodePtr transforms = xmlNewChild(ref, ds, BAD_CAST "Transforms", nullptr);
  xmlNodePtr env = xmlNewChild(transforms, ds, BAD_CAST "Transform", nullptr);
  xmlNewProp(env, BAD_CAST "Algorithm", BAD_CAST kEnveloped);
  xmlNodePtr exc = xmlNewChild(transforms, ds, BAD_CAST "Transform", nullptr);
  xmlNewProp(exc, BAD_CAST "Algorithm", BAD_CAST kExcC14N);
  xmlNodePtr digest_method = xmlNewChild(ref, ds, BAD_CAST "DigestMethod", nullptr);
  xmlNewProp(digest_method, BAD_CAST "Algorithm", BAD_CAST kDigest256);
  xmlNewChild(ref, ds, BAD_CAST "DigestValue", BAD_CAST digest.c_str());
  xmlNodePtr sig_value = xmlNewChild(signature, ds, BAD_CAST "SignatureValue", nullptr);
  xmlNodePtr key_info = xmlNewChild(signature, ds, BAD_CAST "KeyInfo", nullptr);
  xmlNodePtr data = xmlNewChild(key_info, ds, BAD_CAST "X509Data", nullptr);
  xmlNewChild(data, ds, BAD_CAST "X509Certificate", BAD_CAST certificate_der_b64(cert).c_str());
  std::string signed_bytes = canonicalize(signed_info, kExcC14N, "");
  std::string sig = rsa_sign_pkcs1(key, signed_bytes, EVP_sha256());
  xmlNodeSetContent(sig_value, BAD_CAST b64_encode(sig).c_str());
  return serialize_xml(doc.root());
}

}  // namespace iya::saml
