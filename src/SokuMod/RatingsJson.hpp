#pragma once
#include "nlohmann/json.hpp"
#include <stdexcept>
#include <string>

#if defined(_MSC_VER) && !defined(_CPPUNWIND)
#error Ratings JSON handling requires C++ exception unwinding (/EHsc)
#endif

inline nlohmann::json parseRatingsJson(const std::string &text)
{
	// Never let the JSON library's parse-error policy terminate the game.
	auto root = nlohmann::json::parse(text, nullptr, false);
	if (root.is_discarded() || !root.is_object())
		throw std::runtime_error("Invalid ratings JSON response");
	return root;
}
