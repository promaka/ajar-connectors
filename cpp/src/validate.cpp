// SPDX-License-Identifier: Apache-2.0
//
// Mapping validation against the vendored ontology. Mirrors the Rust runtime's
// checks so an embedder linking this SDK gets the same boot-time protection a
// packaged connector has: unknown entity type, ungoverned attribute, or a value
// outside a controlled vocabulary — each reported with the correction when the
// mistake is a case error, and all of them in one call.

#include <ajar/connector.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

#include "../conformance/mini_json.hpp"
#include "ontology_data.h"

namespace ajar {
namespace {

struct AttrDef {
  std::string name;
  std::vector<std::string> values;  // empty: no controlled vocabulary
};

struct TypeDef {
  std::string parent;  // empty at the root
  std::vector<AttrDef> attributes;
};

struct Ontology {
  std::string version;
  std::map<std::string, TypeDef> types;
};

// Parsed once per process; the input is compiled in and immutable.
const Ontology& ontology() {
  static const Ontology ont = [] {
    Ontology o;
    const std::string raw(kAjarOntologyJson, kAjarOntologyJsonLen);
    const mini_json::Value doc = mini_json::Parser(raw).parse();
    o.version = doc.at("version").str;
    for (const auto& t : doc.at("types").array) {
      TypeDef def;
      if (const auto* p = t.find("parent"); p && !p->is_null()) def.parent = p->str;
      if (const auto* attrs = t.find("attributes")) {
        for (const auto& a : attrs->array) {
          AttrDef ad;
          ad.name = a.at("name").str;
          if (const auto* vals = a.find("values"))
            for (const auto& v : vals->array) ad.values.push_back(v.str);
          def.attributes.push_back(std::move(ad));
        }
      }
      o.types.emplace(t.at("id").str, std::move(def));
    }
    return o;
  }();
  return ont;
}

std::string lower(const std::string& s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

// The same name in a different case is the mistake that costs most, so it is
// answered with the correction rather than only the complaint.
template <typename Range>
std::string case_match(const std::string& needle, const Range& candidates) {
  const std::string want = lower(needle);
  for (const auto& c : candidates)
    if (lower(c) == want) return c;
  return {};
}

}  // namespace

std::string ValidationFault::message() const {
  switch (kind) {
    case Kind::UnknownEntityType: {
      std::string m = "entity_type \"" + subject + "\" is not in the ontology";
      if (!suggestion.empty()) m += " (did you mean \"" + suggestion + "\"?)";
      return m;
    }
    case Kind::UnknownAttribute: {
      std::string m = "attribute \"" + subject + "\" is not governed for this entity type";
      if (!suggestion.empty()) m += " (did you mean \"" + suggestion + "\"?)";
      return m + "; it would be discarded, put it in metadata instead";
    }
    case Kind::NotInVocabulary: {
      std::string m = subject + " = \"" + value + "\" is not one of ";
      for (std::size_t i = 0; i < allowed.size(); ++i) {
        if (i) m += ", ";
        m += allowed[i];
      }
      return m + "; values are case-sensitive";
    }
  }
  return {};
}

std::vector<ValidationFault> validate(const DeclaredMapping& mapping) {
  const Ontology& ont = ontology();
  std::vector<ValidationFault> faults;

  // A vendor namespace is registered with the operator, not declared here.
  if (mapping.entity_type.rfind("x:", 0) == 0) return faults;

  const auto it = ont.types.find(mapping.entity_type);
  if (it == ont.types.end()) {
    std::vector<std::string> ids;
    ids.reserve(ont.types.size());
    for (const auto& kv : ont.types) ids.push_back(kv.first);
    faults.push_back({ValidationFault::Kind::UnknownEntityType, mapping.entity_type,
                      {}, case_match(mapping.entity_type, ids), {}});
    // With no recognised type there is nothing to check attributes against, and
    // reporting every attribute as unknown would bury the real fault.
    return faults;
  }

  // Attributes are inherited: walk to the root, first declaration wins.
  std::map<std::string, const AttrDef*> governed;
  for (const TypeDef* t = &it->second;;) {
    for (const auto& a : t->attributes) governed.emplace(a.name, &a);
    if (t->parent.empty()) break;
    const auto up = ont.types.find(t->parent);
    if (up == ont.types.end()) break;
    t = &up->second;
  }

  std::vector<std::string> names;
  names.reserve(governed.size());
  for (const auto& kv : governed) names.push_back(kv.first);

  for (const auto& want : mapping.attributes) {
    if (governed.count(want)) continue;
    faults.push_back({ValidationFault::Kind::UnknownAttribute, want, {},
                      case_match(want, names), {}});
  }

  for (const auto& [name, value] : mapping.fixed_values) {
    const auto def = governed.find(name);
    if (def == governed.end() || def->second->values.empty()) continue;
    const auto& vocab = def->second->values;
    if (std::find(vocab.begin(), vocab.end(), value) == vocab.end())
      faults.push_back({ValidationFault::Kind::NotInVocabulary, name, value,
                        case_match(value, vocab), vocab});
  }

  return faults;
}

std::vector<ValidationFault> validate(const Event& event) {
  DeclaredMapping m;
  m.entity_type = event.entity_type();
  for (const auto& a : event.attributes()) {
    m.attributes.push_back(a.key());
    m.fixed_values.emplace_back(a.key(), a.value());
  }
  return validate(m);
}

const char* ontology_version() { return ontology().version.c_str(); }

}  // namespace ajar
