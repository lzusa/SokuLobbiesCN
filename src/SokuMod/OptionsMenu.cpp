#include "OptionsMenu.hpp"

#include <cmath>
#include <cstdio>
#include <../directx/dinput.h>
#include "IniConfig.hpp"
#include "InputBox.hpp"
#include "LobbyData.hpp"
#include "LobbyMenu.hpp"
#include "createUTFTexture.hpp"
#include "data.hpp"

void displaySokuCursor(SokuLib::Vector2i pos, SokuLib::Vector2u size);

namespace {

std::string decimalValue(unsigned value)
{
	return "Custom (" + std::to_string(value) + ")";
}

std::string colorValue(unsigned value)
{
	char buffer[24];
	std::snprintf(buffer, sizeof(buffer), "Custom (#%06X)", value & 0xFFFFFF);
	return buffer;
}

bool saveUnsigned(const wchar_t *key, unsigned value)
{
	return IniConfig::writeLobbyUnsigned(profilePath, key, value);
}

bool saveString(const wchar_t *key, const wchar_t *value)
{
	return IniConfig::writeLobbyString(profilePath, key, value);
}

void displayTranslucentCursor(SokuLib::Vector2i pos, SokuLib::Vector2u size)
{
	SokuLib::Sprite (&sprites)[3] = *(SokuLib::Sprite (*)[3])0x89A6C0;
	unsigned colors[3][4];

	for (unsigned sprite = 0; sprite < 3; sprite++)
		for (unsigned vertex = 0; vertex < 4; vertex++) {
			colors[sprite][vertex] = sprites[sprite].vertices[vertex].color;
			auto alpha = (colors[sprite][vertex] >> 24) & 0xFF;
			sprites[sprite].vertices[vertex].color =
				(colors[sprite][vertex] & 0x00FFFFFF) | ((alpha * 0x70 / 0xFF) << 24);
		}
	displaySokuCursor(pos, size);
	for (unsigned sprite = 0; sprite < 3; sprite++)
		for (unsigned vertex = 0; vertex < 4; vertex++)
			sprites[sprite].vertices[vertex].color = colors[sprite][vertex];
}

}

OptionsMenu::OptionsMenu(LobbyMenu *parent) :
	_parent(parent)
{
	SokuLib::Vector2i size;

	this->_background.setPosition({32, 42});
	this->_background.setSize({576, 390});
	this->_background.setFillColor(SokuLib::Color{0x10, 0x18, 0x28, 0xE8});
	this->_background.setBorderColor(SokuLib::Color{0xB0, 0xB8, 0xC8, 0xFF});

	this->_title.texture.createFromText("Lobby Options", lobbyData->getFont(24), {400, 40}, &size);
	this->_title.setSize(size.to<unsigned>());
	this->_title.rect.width = size.x;
	this->_title.rect.height = size.y;
	this->_title.setPosition({52, 54});

	this->_hint.texture.createFromText("A / Left / Right: Change    B / ESC: Back", lobbyData->getFont(12), {540, 20}, &size);
	this->_hint.setSize(size.to<unsigned>());
	this->_hint.rect.width = size.x;
	this->_hint.rect.height = size.y;
	this->_hint.setPosition({52, 402});

	this->_status.texture.createFromText("Could not save SokuLobbies.ini; value was not changed.", lobbyData->getFont(12), {540, 20}, &size);
	this->_status.setSize(size.to<unsigned>());
	this->_status.rect.width = size.x;
	this->_status.rect.height = size.y;
	this->_status.setPosition({52, 382});
	this->_status.tint = SokuLib::Color{0xFF, 0x80, 0x80, 0xFF};

	this->_addOption({
		"Chat Popup Mode",
		{{"All", CHAT_POPUP_ALL}, {"Battle Players", CHAT_POPUP_OPPONENTS}, {"Never", CHAT_POPUP_NEVER}},
		[] { return static_cast<unsigned>(chatPopupMode); },
		[](unsigned value) {
			const wchar_t *stored = value == CHAT_POPUP_NEVER ? L"Never" : value == CHAT_POPUP_OPPONENTS ? L"Battle" : L"All";
			if (!saveString(L"ChatPopupMode", stored))
				return false;
			chatPopupMode = static_cast<ChatPopupMode>(value);
			return true;
		}
	});
	this->_addOption({
		"Text Bubbles",
		{{"Off", 0}, {"On", 1}},
		[] { return showTextBubbles ? 1u : 0u; },
		[](unsigned value) {
			if (!saveUnsigned(L"ShowTextBubbles", value != 0))
				return false;
			showTextBubbles = value != 0;
			return true;
		}
	});
	this->_addOption({
		"Max Chat Messages",
		{{"25", 25}, {"50", 50}, {"100", 100}, {"200", 200}},
		[] { return maxChatMessages; },
		[](unsigned value) {
			if (!saveUnsigned(L"MaxChatMessages", value))
				return false;
			maxChatMessages = value;
			return true;
		},
		decimalValue
	});
	this->_addOption({
		"Opponent Chat Color",
		{{"Soft Blue", 0x7FA6D9}, {"Gold", 0xE0B85C}, {"Soft Pink", 0xD990B5}, {"Soft Green", 0x79B88A}, {"Orange", 0xD98B5F}, {"White", 0xFFFFFF}},
		[] { return opponentChatColor & 0xFFFFFF; },
		[](unsigned value) {
			wchar_t buffer[7];
			std::swprintf(buffer, 7, L"%06X", value & 0xFFFFFF);
			if (!saveString(L"OpponentChatColor", buffer))
				return false;
			opponentChatColor = value & 0xFFFFFF;
			return true;
		},
		colorValue
	});
	this->_addOption({
		"Host Preference",
		{{"Client Only", Lobbies::HOSTPREF_CLIENT_ONLY}, {"Host Only", Lobbies::HOSTPREF_HOST_ONLY}, {"No Preference", Lobbies::HOSTPREF_NO_PREF}},
		[] { return hostPref & Lobbies::HOSTPREF_HOST_PREF_MASK; },
		[this](unsigned value) {
			if (!saveUnsigned(L"HostPref", value & Lobbies::HOSTPREF_HOST_PREF_MASK))
				return false;
			hostPref = (hostPref & ~static_cast<unsigned>(Lobbies::HOSTPREF_HOST_PREF_MASK)) | (value & Lobbies::HOSTPREF_HOST_PREF_MASK);
			this->_parent->onHostPrefChanged();
			return true;
		}
	});
	this->_addOption({
		"Accept Relay",
		{{"Off", 0}, {"On", 1}},
		[] { return (hostPref & Lobbies::HOSTPREF_ACCEPT_RELAY) != 0; },
		[this](unsigned value) {
			if (!saveUnsigned(L"AcceptRelay", value != 0))
				return false;
			if (value)
				hostPref |= Lobbies::HOSTPREF_ACCEPT_RELAY;
			else
				hostPref &= ~static_cast<unsigned>(Lobbies::HOSTPREF_ACCEPT_RELAY);
			this->_parent->onHostPrefChanged();
			return true;
		}
	});
	this->_addOption({
		"Accept Hostlist",
		{{"Off", 0}, {"On", 1}},
		[] { return (hostPref & Lobbies::HOSTPREF_ACCEPT_HOSTLIST) != 0; },
		[this](unsigned value) {
			if (!saveUnsigned(L"AcceptHostlist", value != 0))
				return false;
			if (value)
				hostPref |= Lobbies::HOSTPREF_ACCEPT_HOSTLIST;
			else
				hostPref &= ~static_cast<unsigned>(Lobbies::HOSTPREF_ACCEPT_HOSTLIST);
			this->_parent->onHostPrefChanged();
			return true;
		}
	});
	this->_addOption({
		"Quick Messages",
		{{"Edit 1-9", 0}},
		[] { return 0u; },
		[](unsigned) { return true; },
		{},
		[this] {
			this->_editingMessages = true;
			this->_statusTimer = 0;
			playSound(0x28);
		}
	});
	this->_initMessageEditor();
}

OptionsMenu::~OptionsMenu()
{
	if (inputBoxShown)
		closeInputDialog();
}

void OptionsMenu::_addOption(Option option)
{
	SokuLib::Vector2i size;
	auto current = option.get();
	auto found = std::find_if(option.choices.begin(), option.choices.end(), [current](const Choice &choice) {
		return choice.value == current;
	});
	if (found == option.choices.end()) {
		auto label = option.formatCustom ? option.formatCustom(current) : decimalValue(current);
		option.choices.push_back({std::move(label), current});
		option.index = static_cast<unsigned>(option.choices.size() - 1);
	} else
		option.index = static_cast<unsigned>(std::distance(option.choices.begin(), found));
	option.labelSprite.texture.createFromText(option.name.c_str(), lobbyData->getFont(16), {300, 24}, &size);
	option.labelSprite.setSize(size.to<unsigned>());
	option.labelSprite.rect.width = size.x;
	option.labelSprite.rect.height = size.y;
	this->_options.emplace_back(std::move(option));
	this->_refreshValue(this->_options.back());
}

void OptionsMenu::_refreshValue(Option &option)
{
	SokuLib::Vector2i size;
	option.valueSprite.texture.createFromText(option.choices[option.index].label.c_str(), lobbyData->getFont(16), {260, 24}, &size);
	option.valueSprite.setSize(size.to<unsigned>());
	option.valueSprite.rect.width = size.x;
	option.valueSprite.rect.height = size.y;
}

void OptionsMenu::_showSaveError()
{
	this->_statusTimer = 240;
	playSound(0x29);
}

void OptionsMenu::_initMessageEditor()
{
	SokuLib::Vector2i size;
	this->_messagesTitle.texture.createFromText("Quick Messages", lobbyData->getFont(22), {400, 36}, &size);
	this->_messagesTitle.setSize(size.to<unsigned>());
	this->_messagesTitle.rect.width = size.x;
	this->_messagesTitle.rect.height = size.y;
	this->_messagesTitle.setPosition({52, 58});
	this->_messagesHint.texture.createFromText("A / Enter: Edit    B / ESC: Back", lobbyData->getFont(12), {540, 20}, &size);
	this->_messagesHint.setSize(size.to<unsigned>());
	this->_messagesHint.rect.width = size.x;
	this->_messagesHint.rect.height = size.y;
	this->_messagesHint.setPosition({52, 402});
	for (unsigned i = 0; i < 9; i++) {
		this->_messageLabels.emplace_back();
		auto &label = this->_messageLabels.back();
		label.texture.createFromText(std::to_string(i + 1).c_str(), lobbyData->getFont(16), {32, 24}, &size);
		label.setSize(size.to<unsigned>());
		label.rect.width = size.x;
		label.rect.height = size.y;
		this->_messageValues.emplace_back();
		this->_refreshMessageValue(i);
	}
}

void OptionsMenu::_refreshMessageValue(unsigned index)
{
	std::wstring value = quickMessages[index].empty() ? L"(not configured)" : quickMessages[index];
	if (value.size() > 48) {
		value.resize(45);
		if (!value.empty() && value.back() >= 0xD800 && value.back() <= 0xDBFF)
			value.pop_back();
		value += L"...";
	}
	SokuLib::Vector2i size;
	int textureId = 0;
	if (!createTextTexture(textureId, value.c_str(), lobbyData->getFont(16), {450, 24}, &size, true))
		return;
	auto &sprite = this->_messageValues[index];
	sprite.texture.setHandle(textureId, {450, 24});
	sprite.setSize(size.to<unsigned>());
	sprite.rect = {0, 0, size.x, size.y};
}

void OptionsMenu::_openMessageEditor(unsigned index)
{
	std::wstring title = L"Quick Message " + std::to_wstring(index + 1) + L" - Enter: Save / ESC: Cancel";
	setWideInputBoxCallbacks([this, index](const std::wstring &value) {
		wchar_t key[32];
		std::swprintf(key, 32, L"QuickMessage%u", index + 1);
		if (!IniConfig::writeLobbyString(profilePath, key, value)) {
			this->_showSaveError();
			return;
		}
		quickMessages[index] = value;
		this->_refreshMessageValue(index);
		playSound(0x28);
	});
	openWideInputDialog(title.c_str(), quickMessages[index], 512);
}

void OptionsMenu::_updateMessageEditor()
{
	if (SokuLib::checkKeyOneshot(DIK_ESCAPE, 0, 0, 0) || SokuLib::inputMgrs.input.b == 1) {
		this->_editingMessages = false;
		playSound(0x29);
		return;
	}
	if (SokuLib::inputMgrs.input.a == 1 || SokuLib::checkKeyOneshot(DIK_RETURN, 0, 0, 0)) {
		this->_openMessageEditor(this->_messageCursor);
		return;
	}
	if (std::abs(SokuLib::inputMgrs.input.verticalAxis) == 1 ||
		(std::abs(SokuLib::inputMgrs.input.verticalAxis) > 36 && std::abs(SokuLib::inputMgrs.input.verticalAxis) % 6 == 0)) {
		if (SokuLib::inputMgrs.input.verticalAxis > 0)
			this->_messageCursor = (this->_messageCursor + 1) % 9;
		else
			this->_messageCursor = (this->_messageCursor + 8) % 9;
		playSound(0x27);
	}
}

void OptionsMenu::_renderMessageEditor()
{
	this->_background.draw();
	this->_messagesTitle.draw();
	for (unsigned i = 0; i < 9; i++) {
		int y = 108 + static_cast<int>(i) * 30;
		this->_messageLabels[i].setPosition({76, y});
		this->_messageValues[i].setPosition({116, y});
		this->_messageLabels[i].draw();
		this->_messageValues[i].draw();
	}
	displayTranslucentCursor({58, 104 + static_cast<int>(this->_messageCursor) * 30}, {518, 23});
	if (this->_statusTimer)
		this->_status.draw();
	else
		this->_messagesHint.draw();
	inputBoxRender();
}

void OptionsMenu::_applyValue(Option &option, int delta)
{
	int next = static_cast<int>(option.index) + delta;
	if (next < 0)
		next += static_cast<int>(option.choices.size());
	else
		next %= static_cast<int>(option.choices.size());
	if (!option.apply(option.choices[static_cast<unsigned>(next)].value)) {
		this->_showSaveError();
		return;
	}
	option.index = static_cast<unsigned>(next);
	this->_refreshValue(option);
	playSound(0x28);
}

void OptionsMenu::_()
{
	*(int *)0x882a94 = 0x16;
}

int OptionsMenu::onProcess()
{
	if (this->_statusTimer)
		this->_statusTimer--;
	inputBoxUpdate();
	if (inputBoxShown) {
		if (SokuLib::inputMgrs.input.b == 1) {
			closeInputDialog();
			playSound(0x29);
		}
		return true;
	}
	if (this->_editingMessages) {
		this->_updateMessageEditor();
		return true;
	}
	if (SokuLib::checkKeyOneshot(DIK_ESCAPE, 0, 0, 0) || SokuLib::inputMgrs.input.b == 1) {
		playSound(0x29);
		return false;
	}
	if (this->_options.empty())
		return true;
	auto &option = this->_options[this->_cursor];
	if (SokuLib::inputMgrs.input.a == 1) {
		if (option.confirm)
			option.confirm();
		else
			this->_applyValue(option, 1);
		return true;
	}
	if (std::abs(SokuLib::inputMgrs.input.horizontalAxis) == 1 ||
		(std::abs(SokuLib::inputMgrs.input.horizontalAxis) > 36 && std::abs(SokuLib::inputMgrs.input.horizontalAxis) % 6 == 0))
		this->_applyValue(option, SokuLib::inputMgrs.input.horizontalAxis < 0 ? -1 : 1);
	if (std::abs(SokuLib::inputMgrs.input.verticalAxis) == 1 ||
		(std::abs(SokuLib::inputMgrs.input.verticalAxis) > 36 && std::abs(SokuLib::inputMgrs.input.verticalAxis) % 6 == 0)) {
		if (SokuLib::inputMgrs.input.verticalAxis > 0)
			this->_cursor = (this->_cursor + 1) % this->_options.size();
		else
			this->_cursor = (this->_cursor + this->_options.size() - 1) % this->_options.size();
		playSound(0x27);
	}
	return true;
}

int OptionsMenu::onRender()
{
	if (this->_editingMessages) {
		this->_renderMessageEditor();
		return 0;
	}
	this->_background.draw();
	this->_title.draw();
	for (unsigned i = 0; i < this->_options.size(); i++) {
		auto &option = this->_options[i];
		int y = 106 + static_cast<int>(i) * 27;
		option.labelSprite.setPosition({64, y});
		option.valueSprite.setPosition({560 - static_cast<int>(option.valueSprite.getSize().x), y});
		option.labelSprite.draw();
		option.valueSprite.draw();
	}
	displayTranslucentCursor({50, 102 + static_cast<int>(this->_cursor) * 27}, {526, 22});
	if (this->_statusTimer)
		this->_status.draw();
	else
		this->_hint.draw();
	return 0;
}
