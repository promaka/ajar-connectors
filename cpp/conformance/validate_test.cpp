// SPDX-License-Identifier: Apache-2.0
//
// Mapping validation against the vendored ontology: the same cases the Rust
// runtime's tests pin, so the two implementations cannot quietly diverge on
// what counts as a fault.

#include <ajar/connector.hpp>

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) ++failures;
}

ajar::DeclaredMapping mapping(std::string entity_type,
                              std::vector<std::string> attributes = {}) {
  ajar::DeclaredMapping m;
  m.entity_type = std::move(entity_type);
  m.attributes = std::move(attributes);
  return m;
}

}  // namespace

int main() {
  using ajar::ValidationFault;
  using ajar::validate;

  check(validate(mapping("mim:aircraft", {"speed", "hostility", "callsign"})).empty(),
        "a correct mapping passes");

  // The ontology lists every attribute a type allows, including the ones it
  // shares with its parent, and Core reads only that list; so the deliberate
  // narrowings are enforced: a sensor has no speed though its parent equipment
  // does, and only a bare mim:object carries environment.
  check(validate(mapping("mim:aircraft", {"hostility", "speed"})).empty(),
        "an aircraft lists hostility and speed itself");
  check(validate(mapping("mim:equipment", {"speed"})).empty(), "equipment has speed");
  {
    const auto f = validate(mapping("mim:sensor", {"speed"}));
    check(f.size() == 1 && f[0].kind == ValidationFault::Kind::UnknownAttribute &&
              f[0].governed_on == "mim:equipment",
          "a sensor has no speed, and the fault names the parent that has it");
    check(f[0].message().find("not inherited") != std::string::npos,
          "the fault says attributes are not inherited");
  }
  check(validate(mapping("mim:object", {"environment"})).empty(),
        "a bare object carries environment");
  {
    const auto f = validate(mapping("mim:vessel", {"environment"}));
    check(f.size() == 1 && f[0].governed_on == "mim:object",
          "a vessel has no environment; it is governed on mim:object");
  }

  {
    const auto f = validate(mapping("mim:banana"));
    check(f.size() == 1 && f[0].kind == ValidationFault::Kind::UnknownEntityType,
          "an invented entity type is caught");
  }

  {
    const auto f = validate(mapping("mim:Aircraft"));
    check(f.size() == 1 && f[0].suggestion == "mim:aircraft",
          "a case error in the type suggests the real one");
  }

  {
    const auto f = validate(mapping("mim:aircraft", {"speed_kn"}));
    check(f.size() == 1 && f[0].kind == ValidationFault::Kind::UnknownAttribute &&
              f[0].message().find("metadata") != std::string::npos,
          "an undeclared attribute is caught and points at metadata");
  }

  {
    auto m = mapping("mim:aircraft", {"hostility"});
    m.fixed_values.emplace_back("hostility", "friendly");
    const auto f = validate(m);
    bool in_allowed = false;
    if (f.size() == 1)
      for (const auto& v : f[0].allowed)
        if (v == "Friend") in_allowed = true;
    // "friendly" is a different word, not a case slip of "Friend", so no
    // suggestion is correct; the allowed list is the answer. (A true case slip
    // like "friend" would get the suggestion.)
    check(f.size() == 1 && f[0].kind == ValidationFault::Kind::NotInVocabulary &&
              f[0].value == "friendly" && in_allowed,
          "a lowercase hostility is answered with the valid values");

    auto slip = mapping("mim:aircraft", {"hostility"});
    slip.fixed_values.emplace_back("hostility", "friend");
    const auto g = validate(slip);
    check(g.size() == 1 && g[0].suggestion == "Friend",
          "a true case slip gets the exact correction");
  }

  check(validate(mapping("x:acme:radar-hit", {"anything"})).empty(),
        "a vendor namespace is the operator's, not second-guessed");

  check(validate(mapping("mim:aircraft", {"speed_kn", "nonsense"})).size() == 2,
        "every fault is reported in one call");

  {
    // The event overload checks what a mapping actually built.
    const ajar::Event event = ajar::EventBuilder("acme-radar-1", "mim:aircraft")
                                  .new_id()
                                  .now()
                                  .attribute("hostility", "Friend")
                                  .attribute("speed", "231.50")
                                  .build();
    check(validate(event).empty(), "a well-mapped event validates clean");
  }

  {
    ajar::Event event = ajar::EventBuilder("acme-radar-1", "mim:aircraft")
                            .new_id()
                            .now()
                            .attribute("hostility", "friendly")
                            .build();
    const auto f = validate(event);
    check(f.size() == 1 && f[0].kind == ValidationFault::Kind::NotInVocabulary,
          "the event overload catches a vocabulary fault");
  }

  check(std::string(ajar::ontology_version()) == "mim-5.3-conformant-4",
        "the vendored ontology version is reported");

  if (failures) {
    std::printf("\n%d validation test failure(s)\n", failures);
    return 1;
  }
  std::printf("\nall validation checks hold\n");
  return 0;
}
