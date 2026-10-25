#include "ClientTransport.hpp"
#include "ClientChatLog.hpp"
#include "IdleTracking.hpp"
#include "RatingRequestStatus.hpp"
#include "RatingsJson.hpp"
#include "NearbyRatingCards.hpp"
#include "Socket.hpp"
#include "HttpResponseBuffer.hpp"
#include "Utf8Name.hpp"
#include "nlohmann/json.hpp"
#include <limits>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
#ifndef _WIN32
#include <unistd.h>
#endif

static void require(bool condition, const char *message) { if (!condition) throw std::runtime_error(message); }

static void nearbyRatingCardStacking()
{
	struct Point { uint32_t x, y; };
	struct Player { uint32_t id; Point pos; };
	const std::vector<Player> crowd{{1, {100, 100}}, {2, {110, 100}}, {4, {112, 100}}, {3, {112, 100}}, {5, {115, 100}}};
	using namespace NearbyRatingCards;
	require(secondTarget(crowd, 1, 100, 100, 2, false) == 3, "overlapping crowd did not pick one stable second player");
	require(secondTarget(crowd, 1, 100, 100, 2, true) == NO_TARGET, "F8 manual target gained a second card");
	require(secondTarget(crowd, 1, 100, 100, 99, false) == NO_TARGET, "departed primary retained a second card");
	const std::vector<Player> separate{{1, {110, 100}}, {2, {110, 100}}, {3, {180, 100}}, {4, {110, 180}}};
	require(secondTarget(separate, 1, 110, 100, 2, false) == NO_TARGET, "separate players or self triggered a stack");
	const std::vector<Player> distant{{2, {449, 0}}, {3, {451, 0}}};
	require(secondTarget(distant, 1, 0, 0, 2, false) == NO_TARGET, "out-of-range secondary triggered a stack");
	const std::vector<Player> huge{{2, {110, 100}}, {3, {UINT32_MAX, UINT32_MAX}}};
	require(secondTarget(huge, 1, 100, 100, 2, false) == NO_TARGET, "coordinate overflow created false overlap");
	for (unsigned mode = 0; mode < 3; ++mode)
		for (int x : {-200, 0, 320, 640, 900})
			for (int y : {-200, 0, 240, 480, 900})
				for (int offset : {-300, 0, 300}) {
					const auto layout = stackPosition({140, 102}, {230, 52}, x, y, mode, offset, offset);
					require(layout.x >= 4 && layout.x + 230 <= 636, "card stack clipped horizontally");
					require(layout.y >= 4 && layout.secondY + 52 <= 476, "card stack clipped vertically");
					require(layout.secondY >= layout.y + 102 + 6, "second card overlapped the first");
				}
	std::cout << "PASS automatic two-card overlap selection, F8 single-card override and screen-edge layout\n";
}

static void ratingRequestFailures()
{
	using RatingRequests::State;
	std::vector<std::wstring> chinese, english;
	for (auto state : {State::Loading, State::NoRecord, State::Dns, State::Connect, State::Timeout,
		State::Tls, State::Certificate, State::CaFile, State::Transfer, State::InvalidResponse, State::Internal, State::InvalidName}) {
		const RatingRequests::Status status{state};
		require(!RatingRequests::text(status, true).empty() && !RatingRequests::text(status, false).empty(),
			"rating error missing translation");
		for (auto previous : chinese) require(previous != RatingRequests::text(status, true), "different failures share Chinese text");
		for (auto previous : english) require(previous != RatingRequests::text(status, false), "different failures share English text");
		chinese.push_back(RatingRequests::text(status, true));
		english.push_back(RatingRequests::text(status, false));
	}
	for (long http : {403L, 429L, 500L, 503L}) {
		const RatingRequests::Status status{State::Http, http};
		require(RatingRequests::text(status, false).find(std::to_wstring(http)) != std::wstring::npos,
			"HTTP status missing from card text");
	}
	require(RatingRequests::text({State::Loading}, false) != RatingRequests::text({State::NoRecord}, false) &&
		RatingRequests::text({State::InvalidResponse}, true) != RatingRequests::text({State::NoRecord}, true),
		"loading, malformed response and missing record conflated");
	std::cout << "PASS rating DNS/connect/timeout/TLS/CA/HTTP failures and bilingual card messages\n";
}

static void idleReportingClock()
{
	using namespace std::chrono_literals;
	const auto start = IdleTracking::Clock::time_point{} + 1h;
	IdleTracking::LocalClock local;
	local.reset(start);
	require(!local.due(start + 1h), "old server enabled unnegotiated reports");
	local.supported = true;
	require(local.due(start), "capability did not trigger first report");
	local.lastReport = start; local.dirty = false;
	require(!local.due(start + 9s) && local.due(start + 10s), "report interval changed");
	local.setExempt(true, start + 5s);
	require(local.idle(start + 1h) == 0s && local.due(start + 5s), "waiting/playing failed to clear idle");
	local.setExempt(false, start + 2h);
	require(local.idle(start + 2h + 15s) == 15s, "leaving exemption inherited idle");
	local.active(start + 2h + 10s);
	require(local.idle(start + 2h + 15s) == 5s, "chat failed to reset local clock");
	local.reset(start + 3h);
	require(!local.supported && local.idle(start + 3h) == 0s, "rejoin inherited negotiated state");

	IdleTracking::RemoteClock remote;
	remote.accept(200, false, start);
	require(remote.fresh(start + 29s) && !remote.fresh(start + 30s), "report freshness boundary wrong");
	require(remote.idle(start + 10s, start - 1h) == 210s, "server did not extrapolate client duration");
	require(remote.idle(start + 10s, start + 5s) == 5s, "autokick restart did not cap old duration");
	remote.accept(0, true, start);
	require(remote.idle(start + 29s, start - 1h) == 0s, "exemption accumulated idle");
	remote.reset(); require(!remote.fresh(start), "session inherited remote report");
	uint64_t seconds = 0;
	require(IdleTracking::parseSeconds("1200", seconds) && seconds == 1200, "valid report rejected");
	for (const auto *invalid : {"", "-1", "1x", "999999999999", "31536001"})
		require(!IdleTracking::parseSeconds(invalid, seconds), "invalid duration accepted");
	require(IdleTracking::isControl("/__idle 0 1") && IdleTracking::isControl("/__idlecap") &&
		!IdleTracking::isControl("/msg 1 __idlecap") && !IdleTracking::isControl("/__idleother"), "control classification wrong");
	std::cout << "PASS negotiated idle reporting, reset, lease and fallback clocks\n";
}

static void ratingUtf8CrashRegression() {
	// The exact 66-byte name from the eight 0.7.6.2 crash dumps. The old server
	// sent its first 64 bytes, leaving a lone EF prefix at the end.
	const std::string original = u8"\uFF80\uFF99\uFF83\uFF97\uFF80\uE208\uFF87\uFF8F\u30FB\uFF74\uFF8A\uFF72\uFF83\uFF74\uFF7E\uFF8D\uFF70\uFF74\uFF8A\uFF72\uFF83\uFF74";
	const auto truncated = original.substr(0, 64);
	require(original.size() == 66 && truncated.back() == '\xEF', "real crash name fixture changed");
	require(ClientNames::validRatingName(original) && !ClientNames::validRatingName(truncated), "truncated crash name accepted for ratings");
	require(ClientNames::displayName(truncated) == original.substr(0, 63), "incomplete trailing scalar was not removed for display");
	require(truncated.size() == 64 && truncated.back() == '\xEF', "display repair mutated identity bytes");
	for (size_t i = 1; i <= original.size(); ++i) {
		const auto cut = original.substr(0, i);
		require(ClientNames::validRatingName(cut) == (i % 3 == 0), "UTF-8 truncation boundary validation incorrect");
		const auto shown = ClientNames::displayName(cut);
		require(shown.empty() || ClientNames::validRatingName(shown), "display name still contains broken UTF-8");
	}
	for (const auto &invalid : std::vector<std::string>{"\x80", "\xC0\xAF", "\xE0\x80\x80", "\xED\xA0\x80",
		"\xF0\x80\x80\x80", "\xF4\x90\x80\x80", "\xF5\x80\x80\x80", "\xC2", "\xE4\xB8", "\xF0\x9F\x98", std::string("a\0b", 3)}) {
		require(!ClientNames::validRatingName(invalid), "malformed UTF-8 or embedded NUL accepted");
		const auto shown = ClientNames::displayName(invalid);
		require(shown.empty() || ClientNames::validRatingName(shown), "invalid middle sequence remained in display");
	}
	for (const auto &valid : std::vector<std::string>{"Alice", u8"\u65E0\u98CE", "\xC2\x80", "\xE0\xA0\x80", "\xED\x9F\xBF", "\xF0\x90\x80\x80", "\xF4\x8F\xBF\xBF"})
		require(ClientNames::validRatingName(valid) && ClientNames::displayName(valid) == valid, "valid name changed by UTF-8 validation");
	require(ClientNames::displayName(std::string("a\xFF") + "b") == std::string("a\xEF\xBF\xBD") + "b", "invalid middle byte not replaced for display");
	bool reproduced = false;
	try { nlohmann::json request; request["names"] = std::vector<std::string>{"Alice", truncated}; request.dump(); }
	catch (const nlohmann::json::type_error &error) { reproduced = error.id == 316; }
	require(reproduced, "real crash fixture did not reproduce JSON error 316");
	const auto safe = ClientNames::ratingNames({"Alice", truncated, u8"\u65E0\u98CE"});
	nlohmann::json request; request["names"] = safe;
	const auto roundTrip = nlohmann::json::parse(request.dump());
	require(roundTrip["names"].size() == 2 && roundTrip["names"][0] == "Alice", "one damaged name poisoned a valid rating batch");
	require(ClientNames::ratingNames({truncated}).empty(), "invalid-only batch was not skipped");
	unsigned completed = 0, reported = 0;
	require(!runClientTask([] { throw std::runtime_error("invalid rating batch"); }, [&](const char *) { ++reported; }), "failed task reported success");
	require(!runClientTask([] { throw std::bad_alloc(); }, [](const char *) { throw std::bad_alloc(); }), "failed reporting escaped task guard");
	require(runClientTask([&] { ++completed; }, [](const char *) {}) && completed == 1 && reported == 1, "worker could not execute a good task after a bad task");
	std::cout << "PASS real 66/64-byte crash, strict UTF-8, display-only repair, isolated JSON batch and worker continuation\n";
}

static void cancellationAndLatestTaskSafety() {
	// The sender has checked running but deliberately has not entered wait yet.
	std::mutex mutex;
	std::condition_variable wake;
	std::atomic_bool running{true}, releaseWaiter{false};
	std::promise<void> checked;
	auto sender = std::async(std::launch::async, [&] {
		std::unique_lock<std::mutex> lock(mutex);
		require(running, "sender cancelled before race setup");
		checked.set_value();
		while (!releaseWaiter) std::this_thread::yield();
		wake.wait(lock, [&] { return !running.load(); });
	});
	checked.get_future().wait();
	auto stopper = std::async(std::launch::async, [&] { stopClientWaiter(running, mutex, wake); });
	releaseWaiter = true;
	const bool stopped = stopper.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
	const bool joined = sender.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
	if (!stopped || !joined) { running = false; wake.notify_all(); }
	stopper.get(); sender.get();
	require(stopped && joined, "sender cancellation lost its wake notification");

	unsigned cleaned = 0;
	runClientDisconnectCallbacks([] { throw std::bad_alloc(); }, [&] { ++cleaned; });
	require(cleaned == 1, "error callback failure skipped disconnect cleanup");
	runClientDisconnectCallbacks([] {}, [] { throw 42; });
	std::cout << "PASS sender cancellation and independent disconnect cleanup\n";
}

static void httpCallbackSafety() {
	require(validClientGameInfoResult(2, 2, 3, 3, Lobbies::BATTLE_STATUS_WAITING), "waiting host result rejected");
	require(validClientGameInfoResult(2, 2, 3, 3, Lobbies::BATTLE_STATUS_PLAYING), "playing host result rejected");
	require(!validClientGameInfoResult(2, 3, 3, 3, Lobbies::BATTLE_STATUS_PLAYING), "old lobby IP result published");
	require(!validClientGameInfoResult(2, 2, 3, 4, Lobbies::BATTLE_STATUS_PLAYING), "old machine IP result published");
	require(!validClientGameInfoResult(2, 2, 3, 3, Lobbies::BATTLE_STATUS_IDLE), "idle IP result published");
	require(!validClientGameInfoResult(2, 2, 3, 3, Lobbies::BATTLE_STATUS_SPECTATING), "spectator IP result published");
	std::string body;
	require(appendHttpResponse(body, "abcd", 2, 2, 5) == 4 && body == "abcd", "HTTP body append failed");
	require(appendHttpResponse(body, "ef", 1, 2, 5) == 0 && body == "abcd", "HTTP response limit changed retained body");
	require(appendHttpResponse(body, "x", (std::numeric_limits<size_t>::max)(), 2, 5) == 0, "HTTP size multiplication overflow accepted");
	require(appendHttpResponse(body, nullptr, 1, 1, 5) == 0, "HTTP null body accepted");
	require(appendHttpResponse(body, nullptr, 0, 100, 5) == 0, "HTTP zero-length append failed");
	require(appendHttpResponse(body, "x", 1, 1, 3) == 0, "HTTP existing oversized body accepted");
	require(appendHttpResponse(body, "e", 1, 1, 5) == 1 && body == "abcde", "HTTP exact size limit rejected");
	struct FailingBody {
		size_t size() const noexcept { return 0; }
		void append(const char *, size_t) { throw std::bad_alloc(); }
	} failing;
	require(appendHttpResponse(failing, "x", 1, 1) == 0, "HTTP allocation failure escaped C callback");
	std::cout << "PASS HTTP response bounds, overflow and callback allocation failure\n";
}

static void workerExceptionSafety() {
	unsigned stopped = 0, reported = 0;
	runClientWorker([] {}, [&](const char *) { ++reported; }, [&] { ++stopped; });
	require(!reported && !stopped, "normal worker exit incorrectly reported a failure");
	runClientWorker([] { throw std::runtime_error("receive failed"); },
		[&](const char *message) { require(std::string(message) == "receive failed", "exception reason lost"); ++reported; },
		[&] { ++stopped; });
	require(reported == 1 && stopped == 1, "worker exception did not report and cancel");
	runClientWorker([] { throw 42; }, [&](const char *) { ++reported; }, [&] { ++stopped; });
	require(reported == 2 && stopped == 2, "non-standard exception escaped worker guard");
	runClientWorker([] { throw std::bad_alloc(); }, [](const char *) { throw std::bad_alloc(); }, [&] { ++stopped; });
	require(stopped == 3, "reporting failure prevented worker cancellation");
	for (int i = 0; i < 256; ++i)
		require(validClientBattleStatus(static_cast<Lobbies::BattleStatus>(i)) == (i <= 3), "battle status bounds incorrect");
	require(!validClientBattleStatus(static_cast<Lobbies::BattleStatus>(-1)), "negative battle status accepted");
	std::cout << "PASS worker exceptions, failed reporting fallback and battle status bounds\n";
}

static void constructionAndMembershipSafety() {
	for (unsigned failAfter = 0; failAfter < 4; ++failAfter) {
		std::thread workers[3];
		std::atomic_bool running{true};
		bool cleaned = false;
		try {
			ClientConstructionGuard rollback([&]() noexcept {
				running = false;
				for (auto &worker : workers) if (worker.joinable()) worker.join();
				cleaned = true;
			});
			for (unsigned i = 0; i < failAfter; ++i)
				workers[i] = std::thread([&] { while (running) std::this_thread::yield(); });
			throw std::runtime_error("injected construction failure");
		} catch (const std::runtime_error &) {}
		require(cleaned, "construction failure skipped rollback");
		for (const auto &worker : workers) require(!worker.joinable(), "construction left a joinable thread");
	}
	bool cleanupCalled = false;
	{ ClientConstructionGuard rollback([&]() noexcept { cleanupCalled = true; }); rollback.dismiss(); }
	require(!cleanupCalled, "successful construction incorrectly rolled back");
	ClientArcadeMembership members;
	require(members.enter(1, 9) && !members.enter(1, 9) && members.count(9) == 1, "duplicate join inflated occupancy");
	require(members.enter(2, 9) && members.count(9) == 2, "second member not counted");
	require(!members.leave(1, 8) && members.count(9) == 2, "stale leave removed a new membership");
	require(members.enter(1, 8) && members.count(9) == 1 && members.count(8) == 1, "machine transfer retained old membership");
	require(members.leave(2, 9) && !members.leave(2, 9) && members.count(9) == 0, "duplicate leave underflowed occupancy");
	require(!validClientIndex(0, 0) && validClientIndex(9, 10) && !validClientIndex(10, 10) &&
		!validClientIndex(static_cast<size_t>(-1), 10), "asset index boundary checks incorrect");
	std::cout << "PASS partial construction rollback, membership deduplication and asset bounds\n";
}

static void callbackAndCleanupSafety() {
	std::mutex mutex;
	auto failed = runClientWindowCallback("injected input failure", [&]() -> std::optional<int> {
		std::lock_guard<std::mutex> lock(mutex);
		throw std::runtime_error("input failed");
	});
	require(!failed, "failed window callback did not request native fallback");
	require(mutex.try_lock(), "input exception left a mutex locked");
	mutex.unlock();
	unsigned forwarded = 0;
	auto dispatch = [&](int mode) {
		auto result = runClientWindowCallback("injected window callback", [&]() -> std::optional<int> {
			if (mode == 0) return 0;
			if (mode == 1) return std::nullopt;
			throw 42;
		});
		if (result) return *result;
		++forwarded; return 99;
	};
	require(dispatch(0) == 0 && forwarded == 0, "handled zero result incorrectly forwarded");
	require(dispatch(1) == 99 && forwarded == 1, "unhandled message not forwarded exactly once");
	require(dispatch(2) == 99 && forwarded == 2, "throwing callback not forwarded exactly once");
	bool joined = false, released = false;
	{
		ClientConstructionGuard cleanup([&]() noexcept {
			runClientCleanup("injected disconnect callback", [] { throw std::runtime_error("callback failed"); });
			joined = true; released = true;
		});
		runClientCleanup("injected recent player save", [] { throw std::bad_alloc(); });
	}
	require(joined && released, "optional cleanup failure skipped mandatory cleanup");
	std::cout << "PASS window fallback, input lock unwinding and independent cleanup failures\n";
}

static void inboxBoundsAndOwnership() {
	ClientInbox inbox; std::atomic_bool running{true}; char text[] = "original";
	require(!inbox.push(text, ClientInbox::MAX_BYTES + 1, 7, false, running), "oversized frame did not fail immediately");
	require(inbox.push(text, sizeof(text), 7, false, running), "enqueue failed");
	text[0] = '!'; ClientInbox::Frame frame;
	require(inbox.pop(frame) && frame.session == 7 && frame.bytes[0] == 'o', "queued frame aliases producer memory");
	for (size_t i = 0; i < ClientInbox::MAX_CHAT + 10; ++i) inbox.push(text, sizeof(text), 7, true, running);
	require(inbox.takeDropped() == 10, "chat bound not enforced");
	require(inbox.push(text, sizeof(text), 7, false, running), "chat consumed reliable capacity");
	size_t count = 0; while (inbox.pop(frame)) ++count;
	require(count == ClientInbox::MAX_CHAT + 1, "reliable frame lost under chat flood");
	for (size_t i = 0; i < ClientInbox::MAX_FRAMES; ++i) {
		const char value = static_cast<char>(i); inbox.push(&value, 1, i, false, running);
	}
	auto producer = std::async(std::launch::async, [&] { return inbox.push(text, sizeof(text), 9999, false, running); });
	require(producer.wait_for(std::chrono::milliseconds(40)) == std::future_status::timeout, "full reliable queue failed to pause ingress");
	require(inbox.pop(frame) && frame.session == 0, "FIFO first frame incorrect");
	require(producer.wait_for(std::chrono::seconds(2)) == std::future_status::ready && producer.get(), "capacity wake lost");
	for (size_t i = 1; i < ClientInbox::MAX_FRAMES; ++i)
		require(inbox.pop(frame) && frame.session == i, "reliable events reordered");
	require(inbox.pop(frame) && frame.session == 9999, "retained frame lost after pressure");
	inbox.clear();
	for (size_t i = 0; i < ClientInbox::MAX_FRAMES; ++i) inbox.push(text, sizeof(text), 8, false, running);
	auto cancelled = std::async(std::launch::async, [&] { return inbox.push(text, sizeof(text), 8, false, running); });
	running = false; inbox.wake();
	require(cancelled.wait_for(std::chrono::seconds(2)) == std::future_status::ready && !cancelled.get(), "shutdown failed to release paused ingress");
	inbox.clear(); require(inbox.empty(), "session clear retained events");
	std::cout << "PASS immutable FIFO, chat reserve, capacity wake, cancellation and clear\n";
}

static void nonblockingConnect() {
	Socket client; std::atomic_bool running{true};
	const auto listener = ::socket(AF_INET, SOCK_STREAM, 0);
	require(listener != INVALID_SOCKET, "test listener creation failed");
	SOCKET peer = INVALID_SOCKET;
	auto cleanup = [&] {
#ifdef _WIN32
		if (peer != INVALID_SOCKET) closesocket(peer); closesocket(listener);
#else
		if (peer != INVALID_SOCKET) ::close(peer); ::close(listener);
#endif
	};
	try {
		sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		require(::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0 && ::listen(listener, 1) == 0, "test listener bind failed");
#ifdef _WIN32
		int length = sizeof(address);
#else
		socklen_t length = sizeof(address);
#endif
		require(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == 0, "listener address unavailable");
		client.connectWithTimeout("127.0.0.1", ntohs(address.sin_port), std::chrono::seconds(2), running);
		require(client.isOpen(), "timed connect failed"); peer = ::accept(listener, nullptr, nullptr);
		require(peer != INVALID_SOCKET, "test accept failed");
		char byte; const auto result = ::recv(client.getSockFd(), &byte, 1, 0);
#ifdef _WIN32
		require(result < 0 && WSAGetLastError() == WSAEWOULDBLOCK, "client socket was left blocking");
#else
		require(result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "client socket was left blocking");
#endif
		Socket cancelled; running = false;
		cancelled.connectWithTimeout("cancelled.invalid", 1, std::chrono::seconds(2), running);
		require(!cancelled.isOpen(), "cancelled connect published a socket");
	} catch (...) { cleanup(); throw; }
	cleanup(); std::cout << "PASS loopback nonblocking connect and pre-connect cancellation\n";
}

static void chatLogFile() {
	const auto directory = std::filesystem::temp_directory_path() /
		("sokulobbies-client-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
	queueChatLog(directory, "sample\none\rline"); queueChatLog(directory, "second");
	std::filesystem::path file;
	bool found = false;
	for (unsigned i = 0; i < 200 && !found; ++i) {
		if (std::filesystem::exists(directory)) for (const auto &entry : std::filesystem::directory_iterator(directory)) {
			file = entry.path(); std::ifstream input(file); std::string contents((std::istreambuf_iterator<char>(input)), {});
			found = contents.find("sample one line\n") != std::string::npos && contents.find("second\n") != std::string::npos;
		}
		if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	require(found, "asynchronous chat log did not persist ordered sanitized lines");
	std::filesystem::remove(file); std::filesystem::remove(directory);
	std::cout << "PASS asynchronous chat file and newline sanitization\n";
}

int main() {
	try {
		for (const auto &body : {"", "<html>error</html>", "{\"players\":", "[]", "null"}) {
			bool caught = false;
			try { parseRatingsJson(body); } catch (const std::exception &) { caught = true; }
			require(caught, "malformed rating response did not unwind safely");
		}
		require(parseRatingsJson("{\"players\":[]}")["players"].is_array(), "valid rating response rejected");
		require(clientPacketSize(Lobbies::OPCODE_OLLEH) == sizeof(Lobbies::PacketOlleh) &&
			clientPacketSize(Lobbies::OPCODE_MESSAGE) == sizeof(Lobbies::PacketMessage) && clientPacketSize(255) == 0,
			"legacy frame sizes changed");
		nearbyRatingCardStacking(); ratingRequestFailures(); idleReportingClock(); ratingUtf8CrashRegression(); cancellationAndLatestTaskSafety(); httpCallbackSafety(); workerExceptionSafety(); constructionAndMembershipSafety(); callbackAndCleanupSafety();
		inboxBoundsAndOwnership(); nonblockingConnect(); chatLogFile();
		return 0;
	} catch (const std::exception &error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
