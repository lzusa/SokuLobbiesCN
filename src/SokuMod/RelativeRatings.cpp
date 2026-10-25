#include "RelativeRatings.hpp"
#include "RatingsJson.hpp"
#include "RatingsNetworkDiagnostics.hpp"
#include "ClientTransport.hpp"
#include "HttpResponseBuffer.hpp"
#include "Utf8Name.hpp"
#include "ClientPerformance.hpp"

#include <Windows.h>
#include <curl/curl.h>
#include "nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <unordered_set>

namespace {
	using Json = nlohmann::json;
	RatingRequests::Status classifyRatingFailure(CURLcode result, long http) {
		using RatingRequests::State;
		switch (result) {
		case CURLE_OK: return {http == 200 ? State::NoRecord : State::Http, http};
		case CURLE_HTTP_RETURNED_ERROR: return {State::Http, http};
		case CURLE_COULDNT_RESOLVE_HOST: case CURLE_COULDNT_RESOLVE_PROXY: return {State::Dns};
		case CURLE_COULDNT_CONNECT: return {State::Connect};
		case CURLE_OPERATION_TIMEDOUT: return {State::Timeout};
		case CURLE_SSL_CONNECT_ERROR: return {State::Tls};
		case CURLE_PEER_FAILED_VERIFICATION: return {State::Certificate};
		case CURLE_SSL_CACERT_BADFILE: return {State::CaFile};
		case CURLE_FAILED_INIT: case CURLE_OUT_OF_MEMORY: return {State::Internal};
		default: return {State::Transfer};
		}
	}
	bool caBundleExists(const std::wstring &path) {
		std::error_code error;
		return std::filesystem::exists(path, error);
	}
	constexpr std::size_t maxResponseSize = 12u * 1024u * 1024u;
	std::uint64_t fileTimeNow()
	{
		FILETIME value{};
		GetSystemTimeAsFileTime(&value);
		return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
	}

	std::string trim(std::string value)
	{
		auto first = value.find_first_not_of(" \t\r\n");
		if (first == std::string::npos)
			return {};
		auto last = value.find_last_not_of(" \t\r\n");
		return value.substr(first, last - first + 1);
	}

	struct DownloadBuffer {
		std::string body;
		std::atomic_bool *enabled = nullptr;
		std::atomic_bool *stopping = nullptr;
	};

	size_t receiveBody(char *data, size_t size, size_t count, void *context) noexcept
	{
		auto *buffer = static_cast<DownloadBuffer *>(context);
		return buffer ? appendHttpResponse(buffer->body, data, size, count, maxResponseSize) : 0;
	}

	int transferProgress(void *context, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
	{
		auto *buffer = static_cast<DownloadBuffer *>(context);
		return !buffer->enabled->load(std::memory_order_relaxed) || buffer->stopping->load(std::memory_order_relaxed);
	}

	bool validRecord(const RelativeRatings::Rating &record)
	{
		return !record.name.empty() && std::isfinite(record.value) && record.value > 0 &&
			std::isfinite(record.deviation) && record.deviation >= 0;
	}

	std::string optionalString(const Json &object, const char *key)
	{
		auto item = object.find(key);
		return item != object.end() && item->is_string() ? item->get<std::string>() : std::string{};
	}

	std::uint64_t cacheTime(const std::filesystem::path &path)
	{
		WIN32_FILE_ATTRIBUTE_DATA attributes{};
		if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
			return 0;
		return (static_cast<std::uint64_t>(attributes.ftLastWriteTime.dwHighDateTime) << 32) |
			attributes.ftLastWriteTime.dwLowDateTime;
	}
}

RelativeRatings::RelativeRatings(const std::wstring &moduleDirectory) :
	_cachePath((std::filesystem::path(moduleDirectory) / L"ratings-cache").wstring()),
	_mapPath((std::filesystem::path(moduleDirectory) / L"ratings-map.tsv").wstring()),
	_caPath((std::filesystem::path(moduleDirectory) / L"assets/ratings/curl-ca-bundle.crt").wstring()),
	_debugLogPath((std::filesystem::path(moduleDirectory) / L"ratings-debug.log").wstring())
{
}

void RelativeRatings::_debugLog(const std::string &message) const
{
#ifdef SOKU_RATINGS_DIAGNOSTICS
	static std::mutex logMutex;
	std::lock_guard<std::mutex> lock(logMutex);
	try {
		SYSTEMTIME now{};
		GetLocalTime(&now);
		std::ofstream file(_debugLogPath, std::ios::binary | std::ios::app);
		if (file)
			file << std::setfill('0') << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute << ':' <<
				std::setw(2) << now.wSecond << '.' << std::setw(3) << now.wMilliseconds << ' ' << message << "\r\n";
	} catch (...) {
	}
#else
	(void)message;
#endif
}

RelativeRatings::~RelativeRatings()
{
	stop();
}

void RelativeRatings::setEnabled(bool enabled)
{
	if (enabled && _workerFailed.load()) {
		if (_worker.joinable()) _worker.join();
		_workerFailed = false;
	}
	_enabled.store(enabled, std::memory_order_relaxed);
	if (enabled && !_worker.joinable()) {
		_stopping.store(false, std::memory_order_relaxed);
		try { _worker = std::thread(&RelativeRatings::_runGuarded, this); }
		catch (...) { _enabled = false; _workerFailed = true; }
	}
	_wake.notify_all();
	_debugLog(std::string("ratings enabled=") + (enabled ? "true" : "false"));
}

void RelativeRatings::stop()
{
	_stopping.store(true, std::memory_order_relaxed);
	_enabled.store(false, std::memory_order_relaxed);
	_wake.notify_all();
	if (_worker.joinable())
		_worker.join();
}

bool RelativeRatings::setMapping(const std::string &profile, const std::string &account)
{
	const auto cleanProfile = trim(profile);
	const auto cleanAccount = trim(account);
	if (cleanProfile.empty() || cleanProfile.size() >= 129 || cleanAccount.size() >= 129 ||
		!ClientNames::validRatingName(cleanProfile) || (!cleanAccount.empty() && !ClientNames::validRatingName(cleanAccount)) ||
		cleanProfile.find_first_of("\t\r\n") != std::string::npos || cleanAccount.find_first_of("\t\r\n") != std::string::npos)
		return false;
	std::vector<std::string> lines;
	{
		std::ifstream file(_mapPath, std::ios::binary);
		std::string line;
		while (std::getline(file, line)) {
			auto tab = line.find('\t');
			if (tab != std::string::npos && trim(line.substr(0, tab)) == cleanProfile)
				continue;
			lines.push_back(std::move(line));
		}
	}
	if (!cleanAccount.empty())
		lines.push_back(cleanProfile + "\t" + cleanAccount);
	auto temporary = _mapPath + L".tmp";
	try {
		{
			std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
			for (const auto &line : lines)
				file << line << "\r\n";
			if (!file)
				return false;
		}
		if (!MoveFileExW(temporary.c_str(), _mapPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			DeleteFileW(temporary.c_str());
			return false;
		}
	} catch (...) {
		DeleteFileW(temporary.c_str());
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(_mutex);
		if (cleanAccount.empty())
			_manualAccounts.erase(cleanProfile);
		else
			_manualAccounts[cleanProfile] = cleanAccount;
	}
	return true;
}

bool RelativeRatings::lookup(const std::string &profile, Rating &rating) const
{
	ClientPerformance::Scope performance(ClientPerformance::Stage::RatingLookup);
	const auto name = trim(profile);
	if (!ClientNames::validRatingName(name)) {
		if (!name.empty()) {
			const auto now = GetTickCount64();
			auto last = _lastInvalidNameLogAt.load();
			if (now - last >= 10000 && _lastInvalidNameLogAt.compare_exchange_strong(last, now))
				runClientTask([&] { _debugLog("ratings lookup skipped: invalid UTF-8 name bytes=" + std::to_string(name.size())); }, [](const char *) {});
		}
		return false;
	}
	std::lock_guard<std::mutex> lock(_mutex);
	if (_enabled.load(std::memory_order_relaxed)) {
		const auto now = fileTimeNow();
		auto checked = _profileChecked.find(name);
		if ((checked == _profileChecked.end() || now < checked->second || now - checked->second > 6000000000ULL) && _pendingProfiles.size() < 1000) {
			_profileChecked[name] = now;
			_pendingProfiles.push_back(name);
			_profileStatus[name] = {RatingRequests::State::Loading};
			_wake.notify_all();
		}
	}
	auto mapping = _manualAccounts.find(name);
	if (mapping != _manualAccounts.end()) {
		auto byHandle = _byHandle.find(mapping->second);
		if (byHandle != _byHandle.end()) {
			rating = byHandle->second;
			return true;
		}
		auto byName = _byName.find(mapping->second);
		if (byName != _byName.end() && _nameCounts.at(mapping->second) == 1) {
			rating = byName->second;
			return true;
		}
	}
	auto byQuery = _byQuery.find(name);
	if (byQuery != _byQuery.end()) {
		rating = byQuery->second;
		return true;
	}
	auto claimed = _profileHandles.find(name);
	if (claimed != _profileHandles.end()) {
		auto account = _byHandle.find(claimed->second);
		if (account != _byHandle.end()) {
			rating = account->second;
			return true;
		}
	}
	auto playedAs = _byPlayedAs.find(name);
	if (playedAs != _byPlayedAs.end()) {
		rating = playedAs->second;
		return true;
	}
	auto byName = _byName.find(name);
	if (byName == _byName.end() || _nameCounts.at(name) != 1)
		return false;
	rating = byName->second;
	return true;
}

bool RelativeRatings::hasData() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return !_byName.empty();
}

RatingRequests::Status RelativeRatings::requestStatus(const std::string &profile) const
{
	const auto name = trim(profile);
	if (!ClientNames::validRatingName(name)) return {RatingRequests::State::InvalidName};
	if (_workerFailed.load()) return {RatingRequests::State::Internal};
	std::lock_guard<std::mutex> lock(_mutex);
	const auto found = _profileStatus.find(name);
	return found == _profileStatus.end() ? RatingRequests::Status{} : found->second;
}

void RelativeRatings::_loadMappings()
{
	std::unordered_map<std::string, std::string> mappings;
	std::ifstream file(_mapPath, std::ios::binary);
	std::string line;
	while (std::getline(file, line)) {
		if (line.empty() || line[0] == '#')
			continue;
		auto tab = line.find('\t');
		if (tab == std::string::npos)
			continue;
		auto profile = trim(line.substr(0, tab));
		auto account = trim(line.substr(tab + 1));
		if (ClientNames::validRatingName(profile) && ClientNames::validRatingName(account) && profile.size() < 129 && account.size() < 129)
			mappings.emplace(std::move(profile), std::move(account));
	}
	std::lock_guard<std::mutex> lock(_mutex);
	_manualAccounts.swap(mappings);
}

bool RelativeRatings::_publish(const std::string &text)
{
	try {
		Json root = parseRatingsJson(text);
		if (!root.is_object() || !root.contains("players") || !root["players"].is_array())
			return false;
		std::unordered_map<std::string, Rating> playedAs;
		std::unordered_map<std::string, Rating> byName;
		std::unordered_map<std::string, Rating> byHandle;
		std::unordered_map<std::string, unsigned> nameCounts;
		std::size_t total = 0;
		for (const auto &entry : root["players"]) {
			if (!entry.is_object())
				return false;
			Rating record;
			record.name = optionalString(entry, "name");
			record.playedAs = optionalString(entry, "playedAs");
			record.handle = optionalString(entry, "handle");
			record.value = entry.value("rating", 0.0);
			record.deviation = entry.value("rd", 0.0);
			record.games = entry.value("games", 0u);
			if (!validRecord(record))
				return false;
			if (entry.contains("characters") && entry["characters"].is_array()) {
				for (const auto &character : entry["characters"]) {
					if (!character.is_object())
						continue;
					CharacterRating item;
					item.code = character.value("character", std::string{});
					item.rating = character.value("rating", 0.0);
					item.games = character.value("games", 0u);
					if (item.code.empty() || !std::isfinite(item.rating) || item.rating <= 0)
						continue;
					record.characters.push_back(std::move(item));
				}
				std::stable_sort(record.characters.begin(), record.characters.end(), [](const auto &left, const auto &right) {
					return left.games == right.games ? left.rating > right.rating : left.games > right.games;
				});
				if (record.characters.size() > 4)
					record.characters.resize(4);
			}
			++nameCounts[record.name];
			if (!record.playedAs.empty())
				playedAs.emplace(record.playedAs, record);
			if (!record.handle.empty())
				byHandle.emplace(record.handle, record);
			byName.emplace(record.name, std::move(record));
			if (++total > 12000)
				return false;
		}
		if (total == 0)
			return false;
		std::lock_guard<std::mutex> lock(_mutex);
		for (auto &entry : playedAs)
			_byPlayedAs.insert_or_assign(entry.first, std::move(entry.second));
		for (auto &entry : byHandle)
			_byHandle.insert_or_assign(entry.first, std::move(entry.second));
		for (auto &entry : byName) {
			_nameCounts[entry.first] = 1;
			_byName.insert_or_assign(entry.first, std::move(entry.second));
		}
		for (const auto &entry : root["players"])
			if (entry.is_object()) {
				auto query = optionalString(entry, "query");
				auto handle = optionalString(entry, "handle");
				auto playedAs = optionalString(entry, "playedAs");
				auto name = optionalString(entry, "name");
				if (query.empty()) continue;
				if (!handle.empty()) {
					auto found = _byHandle.find(handle);
					if (found != _byHandle.end()) { _byQuery.insert_or_assign(query, found->second); continue; }
				}
				if (!playedAs.empty()) {
					auto found = _byPlayedAs.find(playedAs);
					if (found != _byPlayedAs.end()) { _byQuery.insert_or_assign(query, found->second); continue; }
				}
				auto found = _byName.find(name);
				if (found != _byName.end()) _byQuery.insert_or_assign(query, found->second);
			}
		return true;
	} catch (...) {
		return false;
	}
}

void RelativeRatings::_downloadProfiles(const std::vector<std::string> &profiles)
{
	ClientPerformance::Scope performance(ClientPerformance::Stage::RatingBatch);
	std::error_code fsError;
	std::filesystem::create_directories(_cachePath, fsError);
	const auto cacheFileFor = [&](const std::string &name) {
		std::ostringstream out;
		out << std::hex << std::setw(16) << std::setfill('0') << std::hash<std::string>{}(name) << ".json";
		return std::filesystem::path(_cachePath) / out.str();
	};
	std::vector<std::string> pending;
	for (const auto &profile : profiles) {
		if (!ClientNames::validRatingName(profile)) continue;
		const auto path = cacheFileFor(profile);
		const auto written = cacheTime(path);
		bool cacheLoaded = false;
		if (written) {
			try {
				std::ifstream file(path, std::ios::binary | std::ios::ate);
				auto length = file.tellg();
				if (file && length > 0 && static_cast<std::uint64_t>(length) <= 64u * 1024u) {
					std::string json(static_cast<std::size_t>(length), '\0');
					file.seekg(0);
					file.read(json.data(), static_cast<std::streamsize>(length));
					if (file) cacheLoaded = _publish(json);
				}
			} catch (...) {}
		}
		constexpr std::uint64_t cacheLifetime = 6000000000ULL;
		if (!cacheLoaded || !written || fileTimeNow() < written || fileTimeNow() - written >= cacheLifetime)
			pending.push_back(profile);
		else {
			std::lock_guard<std::mutex> lock(_mutex);
			_profileChecked[profile] = written;
			_profileStatus[profile] = {RatingRequests::State::NoRecord};
		}
	}
	_debugLog("profile batch requested=" + std::to_string(profiles.size()) + " cache_miss=" + std::to_string(pending.size()));
	if (pending.empty()) return;

	std::string lastFetchInfo;
	RatingRequests::Status lastFailure{RatingRequests::State::Internal};
	auto fetch = [&](const std::string &url, const std::string *postBody, std::string &body, const std::string &label) {
		DownloadBuffer response{{}, &_enabled, &_stopping};
		curl_slist *headers = nullptr;
		ClientConstructionGuard freeHeaders([&]() noexcept { curl_slist_free_all(headers); });
		char errorBuffer[CURL_ERROR_SIZE]{};
		const auto caPath = std::filesystem::path(_caPath).string();
		// Destroy curl before the callback buffers and header list, including
		// when formatting/logging a request result throws.
		std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> request(curl_easy_init(), &curl_easy_cleanup);
		if (!request) {
			lastFailure = {RatingRequests::State::Internal};
			lastFetchInfo = label + " curl init failed";
			return false;
		}
		auto *curl = request.get();
		if (postBody) {
			headers = curl_slist_append(headers, "Content-Type: application/json");
			if (!headers) throw std::bad_alloc();
		}
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
		curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
		curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 6L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl, CURLOPT_CAINFO, caPath.c_str());
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "SokuLobbies-RelativeRatings/1.0");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveBody);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, transferProgress);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &response);
		if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		if (postBody) {
			curl_easy_setopt(curl, CURLOPT_POST, 1L);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postBody->c_str());
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(postBody->size()));
		}
		_debugLog("request start: " + label + " backend=mbedTLS route=default verify_peer=true verify_host=true connect_timeout=6s timeout=15s");
		const auto result = curl_easy_perform(curl);
		long code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		lastFailure = classifyRatingFailure(result, code);
		lastFetchInfo = label + " result=" + curl_easy_strerror(result) + " http=" + std::to_string(code) +
			" bytes=" + std::to_string(response.body.size());
#ifdef SOKU_RATINGS_DIAGNOSTICS
		char *remote = nullptr;
		char *local = nullptr;
		long port = 0, osError = 0, verify = 0, tunnelStatus = 0;
		double dns = 0, tcp = 0, tls = 0, firstByte = 0, total = 0;
		curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &remote);
		curl_easy_getinfo(curl, CURLINFO_LOCAL_IP, &local);
		curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &port);
		curl_easy_getinfo(curl, CURLINFO_OS_ERRNO, &osError);
		curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify);
		curl_easy_getinfo(curl, CURLINFO_HTTP_CONNECTCODE, &tunnelStatus);
		curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &dns);
		curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &tcp);
		curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &tls);
		curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &firstByte);
		curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);
		lastFetchInfo += " curl_code=" + std::to_string(result) + " remote=[" + (remote ? remote : "unknown") + "]:" +
			std::to_string(port) + " local=[" + (local ? local : "unknown") + "] os_error=" + std::to_string(osError) +
			" verify_result=" + std::to_string(verify) + " proxy_connect_http=" + std::to_string(tunnelStatus) +
			" cumulative_ms[dns,tcp,tls,first_byte,total]=" + std::to_string(dns * 1000) + "," +
			std::to_string(tcp * 1000) + "," + std::to_string(tls * 1000) + "," +
			std::to_string(firstByte * 1000) + "," + std::to_string(total * 1000);
		if (result == CURLE_SSL_CONNECT_ERROR) lastFetchInfo += " category=TLS_handshake_failed_or_reset";
		else if (result == CURLE_PEER_FAILED_VERIFICATION || result == CURLE_SSL_CACERT_BADFILE)
			lastFetchInfo += " category=certificate_or_CA_file";
#endif
		if (result != CURLE_OK && errorBuffer[0])
			lastFetchInfo += " detail=" + std::string(errorBuffer);
		_debugLog("request end: " + lastFetchInfo);
#ifdef SOKU_RATINGS_NETWORK_PROBE
		const bool transportFailure = result == CURLE_SSL_CONNECT_ERROR || result == CURLE_COULDNT_CONNECT ||
			result == CURLE_COULDNT_RESOLVE_HOST || result == CURLE_OPERATION_TIMEDOUT ||
			result == CURLE_RECV_ERROR || result == CURLE_SEND_ERROR || result == CURLE_GOT_NOTHING;
		if (transportFailure && !_networkProbeDone && _enabled.load() && !_stopping.load()) {
			_networkProbeDone = true;
			try {
				probeRatingsNetwork(url, postBody, caPath, _enabled, _stopping,
					[this](const std::string &entry) { _debugLog(entry); });
			} catch (const std::exception &error) {
				_debugLog(std::string("network comparison stopped: ") + error.what());
			}
		}
#endif
		if (result != CURLE_OK || code != 200) return false;
		body = std::move(response.body);
		if (body.empty()) lastFailure = {RatingRequests::State::InvalidResponse};
		return !body.empty();
	};
	auto queryBatch = [&](const std::vector<std::string> &names, std::string &body) {
		const auto safeNames = ClientNames::ratingNames(names);
		if (safeNames.empty()) { lastFetchInfo = "No valid UTF-8 rating names"; return false; }
		Json request;
		request["names"] = safeNames;
		const auto postBody = request.dump();
		return fetch("https://soku.cleista.cc/api/v1/ratings/players", &postBody, body, "ratings/players POST");
	};

	std::string body;
	if (!queryBatch(pending, body)) {
		_debugLog("batch request failed: " + lastFetchInfo + " ca_bundle_exists=" +
			(caBundleExists(_caPath) ? "true" : "false"));
		std::lock_guard<std::mutex> lock(_mutex);
		for (const auto &name : pending) {
			_profileChecked[name] = fileTimeNow() - 5400000000ULL;
			_profileStatus[name] = lastFailure;
		}
		return;
	}
	const auto now = fileTimeNow();
	const bool published = _publish(body);
	std::unordered_set<std::string> foundNames;
	std::vector<std::pair<std::string, std::string>> aliases;
	std::size_t responseRecords = 0;
	bool validResponse = false;
	try {
		auto root = parseRatingsJson(body);
		if (root.contains("players") && root["players"].is_array()) {
			validResponse = true;
			responseRecords = root["players"].size();
			for (const auto &entry : root["players"]) {
				const auto query = optionalString(entry, "query");
				const auto handle = optionalString(entry, "handle");
				if (!query.empty()) foundNames.insert(query);
				if (!query.empty() && !handle.empty()) aliases.emplace_back(query, handle);
			}
		}
	} catch (...) {}
	if (!validResponse || (responseRecords && !published)) {
		std::lock_guard<std::mutex> lock(_mutex);
		for (const auto &name : pending) {
			_profileStatus[name] = {RatingRequests::State::InvalidResponse};
			_profileChecked[name] = now - 5400000000ULL;
		}
		return;
	}
	std::unordered_map<std::string, RatingRequests::Status> aliasErrors;
	_debugLog("batch response: " + lastFetchInfo + " records=" + std::to_string(responseRecords) +
		" published=" + (published ? "true" : "false"));
	std::size_t aliasAttempts = 0;
	std::size_t aliasFailures = 0;
	for (const auto &name : pending) {
		if (foundNames.count(name)) continue;
		std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> request(curl_easy_init(), &curl_easy_cleanup);
		if (!request) { aliasErrors[name] = {RatingRequests::State::Internal}; continue; }
		auto *curl = request.get();
		char *encoded = curl_easy_escape(curl, name.c_str(), static_cast<int>(name.size()));
		ClientConstructionGuard freeEncoded([&]() noexcept { curl_free(encoded); });
		std::string mapping;
		if (encoded) {
			++aliasAttempts;
			if (!fetch("https://soku.cleista.cc/api/names/profiles?name=" + std::string(encoded), nullptr, mapping, "names/profiles GET")) {
				++aliasFailures;
				aliasErrors[name] = lastFailure;
				continue;
			}
		}
		else { aliasErrors[name] = {RatingRequests::State::Internal}; continue; }
		try {
			auto root = parseRatingsJson(mapping);
			if (!root.is_object()) throw std::runtime_error("Invalid alias response");
			auto item = root.find(name);
			if (item != root.end() && item->is_object()) {
				auto handle = optionalString(*item, "handle");
				if (!handle.empty()) aliases.emplace_back(name, std::move(handle));
			}
		} catch (...) {
			if (!aliasErrors.count(name)) aliasErrors[name] = {RatingRequests::State::InvalidResponse};
		}
	}
	if (aliasFailures)
		_debugLog("profile alias fallback failures=" + std::to_string(aliasFailures) + "/" + std::to_string(aliasAttempts) +
			" last=" + lastFetchInfo);
	if (!aliases.empty()) {
		std::vector<std::string> handles;
		for (const auto &alias : aliases) handles.push_back("@" + alias.second);
		std::string handleBody;
		if (queryBatch(handles, handleBody)) {
			const bool handlePublished = _publish(handleBody);
			if (!handlePublished) {
				try {
					const auto parsed = parseRatingsJson(handleBody);
					if (!parsed.contains("players") || !parsed["players"].is_array() || !parsed["players"].empty())
						throw std::runtime_error("Invalid handle response");
				} catch (...) {
					for (const auto &alias : aliases) aliasErrors[alias.first] = {RatingRequests::State::InvalidResponse};
				}
			}
			_debugLog("handle batch response: " + lastFetchInfo + " published=" + (handlePublished ? "true" : "false"));
			try {
				auto root = parseRatingsJson(handleBody);
				if (root.contains("players") && root["players"].is_array()) {
					std::lock_guard<std::mutex> lock(_mutex);
					for (const auto &entry : root["players"]) {
						auto query = optionalString(entry, "query");
						if (query.size() > 1 && query[0] == '@')
							for (const auto &alias : aliases)
								if (query.substr(1) == alias.second) {
									auto found = _byHandle.find(alias.second);
									if (found != _byHandle.end()) {
										_byQuery.insert_or_assign(alias.first, found->second);
										_profileHandles[alias.first] = alias.second;
									}
								}
					}
				}
			} catch (...) {}
		}
		else for (const auto &alias : aliases) aliasErrors[alias.first] = lastFailure;
	}
	for (const auto &name : pending) {
		std::lock_guard<std::mutex> lock(_mutex);
		_profileChecked[name] = foundNames.count(name) ? now : now - 5400000000ULL;
		auto failure = aliasErrors.find(name);
		_profileStatus[name] = failure == aliasErrors.end() ? RatingRequests::Status{RatingRequests::State::NoRecord} : failure->second;
	}
	_debugLog("batch complete requested=" + std::to_string(pending.size()) + " matched=" + std::to_string(foundNames.size()) +
		" aliases=" + std::to_string(aliases.size()) + " rating_data_loaded=" + (hasData() ? "true" : "false"));
	// Persist each response row separately so future visits only read the names requested.
	try {
		auto root = parseRatingsJson(body);
		if (root.contains("players") && root["players"].is_array())
			for (const auto &entry : root["players"]) {
				auto query = optionalString(entry, "query");
				if (query.empty()) continue;
				Json single;
				single["players"] = Json::array({entry});
				auto file = cacheFileFor(query);
				std::ofstream output(file, std::ios::binary | std::ios::trunc);
				auto serialized = single.dump();
				output.write(serialized.data(), static_cast<std::streamsize>(serialized.size()));
			}
	} catch (...) {}
}

void RelativeRatings::_runGuarded() noexcept
{
	runClientWorker([this] { _run(); }, [this](const char *reason) {
		_debugLog(std::string("rating worker stopped: ") + reason);
	}, [this]() noexcept {
		_enabled = false;
		_stopping = true;
		_workerFailed = true;
		_wake.notify_all();
	});
}

void RelativeRatings::_run()
{
	_loadMappings();
#ifdef SOKU_RATINGS_NETWORK_PROBE
	logRatingsNetworkEnvironment([this](const std::string &entry) { _debugLog(entry); });
#endif
	_debugLog(std::string("worker started ca_bundle_exists=") + (caBundleExists(_caPath) ? "true" : "false"));
	while (!_stopping.load(std::memory_order_relaxed)) {
#ifdef SOKU_CLIENT_PERFORMANCE
		{
			std::lock_guard<std::mutex> lock(_mutex);
			ClientPerformance::gauge(ClientPerformance::Gauge::RatingPending, _pendingProfiles.size());
			ClientPerformance::gauge(ClientPerformance::Gauge::RatingCache, _byQuery.size());
		}
#endif
		if (!_enabled.load(std::memory_order_relaxed)) {
			std::unique_lock<std::mutex> lock(_mutex);
			_wake.wait(lock, [this] { return _stopping.load(std::memory_order_relaxed) || _enabled.load(std::memory_order_relaxed); });
			continue;
		}
		{
			std::unique_lock<std::mutex> lock(_mutex);
			_wake.wait_for(lock, std::chrono::milliseconds(150), [this] {
				return _stopping.load(std::memory_order_relaxed) || !_enabled.load(std::memory_order_relaxed);
			});
		}
		std::vector<std::string> pendingProfiles;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			pendingProfiles.swap(_pendingProfiles);
		}
		if (!pendingProfiles.empty()) {
			const bool completed = runClientTask([&] { _downloadProfiles(pendingProfiles); }, [this](const char *reason) {
				_debugLog(std::string("rating batch failed; worker continues: ") + reason);
			});
			if (!completed) {
				{
					std::lock_guard<std::mutex> lock(_mutex);
					for (const auto &profile : pendingProfiles) _profileStatus[profile] = {RatingRequests::State::Internal};
				}
				// Retain published data and the existing per-name query cooldown.
				// Wait rather than spin if more incoming names keep causing errors.
				std::unique_lock<std::mutex> lock(_mutex);
				_wake.wait_for(lock, std::chrono::seconds(5), [this] { return _stopping.load() || !_enabled.load(); });
			}
			continue;
		}
		std::unique_lock<std::mutex> lock(_mutex);
		_wake.wait(lock, [this] {
			return _stopping.load(std::memory_order_relaxed) || !_enabled.load(std::memory_order_relaxed) || !_pendingProfiles.empty();
		});
	}
}
