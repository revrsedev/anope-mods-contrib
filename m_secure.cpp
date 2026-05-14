/*
2024 Jean "reverse" Chevronnet
Module for Anope IRC Services v2.1.
SeCuRe will ban any proxy IPs using proxycheck.io API.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/// $LinkerFlags: -libcurl -lcrypto -lssl -lcurl

#include "module.h"
#include <map>
#include <ctime>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <set>

// Move ProxyCacheEntry and ProxyCache outside the class
struct ProxyCacheEntry {
	bool is_proxy;
	time_t timestamp;
};

class ProxyCache {
	std::map<std::string, ProxyCacheEntry> cache;
	const int expiry_seconds = 86400; // 1 day
public:
	bool get(const std::string& ip, bool& is_proxy) {
		auto it = cache.find(ip);
		if (it != cache.end()) {
			time_t now = std::time(nullptr);
			if (now - it->second.timestamp < expiry_seconds) {
				is_proxy = it->second.is_proxy;
				return true;
			} else {
				cache.erase(it);
			}
		}
		return false;
	}
	void set(const std::string& ip, bool is_proxy) {
		cache[ip] = {is_proxy, std::time(nullptr)};
	}
};

class SeCuReModule : public Module
{
	BotInfo *secureBot = nullptr;
	ProxyCache proxyCache;
	std::string proxycheck_api_key;
	std::string log_channel_name;
	std::set<std::string> whitelisted_servers;
	std::string wildcard_server;

public:
	SeCuReModule(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, VENDOR)
	{
		this->SetAuthor("reverse");
		this->SetVersion("1.0");
		// Check API key and log channel on module load
		Configuration::Block &config = Config->GetModule(this);
		this->proxycheck_api_key = config.Get<const Anope::string>("proxycheck_api_key", "").str();
		this->log_channel_name = config.Get<const Anope::string>("log_channel", "#services").str();
		this->wildcard_server = config.Get<const Anope::string>("wildcard_server", "").str();
		// Load whitelist_servers from config (space or comma separated)
		std::string whitelist = config.Get<const Anope::string>("whitelist_servers", "").str();
		whitelisted_servers.clear();
		std::string delim = (whitelist.find(',') != std::string::npos) ? "," : " ";
		size_t start = 0, end;
		while ((end = whitelist.find(delim, start)) != std::string::npos) {
			std::string s = whitelist.substr(start, end - start);
			if (!s.empty()) whitelisted_servers.insert(s);
			start = end + delim.length();
		}
		std::string last = whitelist.substr(start);
		if (!last.empty()) whitelisted_servers.insert(last);
		if (this->proxycheck_api_key.empty()) {
			throw ModuleException("m_secure: proxycheck_api_key is not set in anope.conf, refusing to load.");
		}
	}

	void OnReload(Configuration::Conf &conf)
	{
		Configuration::Block &config = conf.GetModule(this);
		this->proxycheck_api_key = config.Get<const Anope::string>("proxycheck_api_key", "").str();
		this->log_channel_name = config.Get<const Anope::string>("log_channel", "#services").str();
		this->wildcard_server = config.Get<const Anope::string>("wildcard_server", "").str();
		// Reload whitelist_servers
		std::string whitelist = config.Get<const Anope::string>("whitelist_servers", "").str();
		whitelisted_servers.clear();
		std::string delim = (whitelist.find(',') != std::string::npos) ? "," : " ";
		size_t start = 0, end;
		while ((end = whitelist.find(delim, start)) != std::string::npos) {
			std::string s = whitelist.substr(start, end - start);
			if (!s.empty()) whitelisted_servers.insert(s);
			start = end + delim.length();
		}
		std::string last = whitelist.substr(start);
		if (!last.empty()) whitelisted_servers.insert(last);
		if (this->proxycheck_api_key.empty()) {
			throw ModuleException("m_secure: proxycheck_api_key is not set in anope.conf, refusing to reload.");
		}
		CreateBot();
	}

	void OnModuleLoad()
	{
		Configuration::Block &config = Config->GetModule(this);
		this->proxycheck_api_key = config.Get<const Anope::string>("proxycheck_api_key", "").str();
		CreateBot();
	}

	void OnModuleUnload()
	{
		if (secureBot)
		{
			delete secureBot;
			secureBot = nullptr;
		}
	}

	// Bridge base-class hooks (with User*/Module* args) to our parameterless versions
	void OnModuleLoad(User *u, Module *m) override
	{
		Module::OnModuleLoad(u, m);
		OnModuleLoad();
	}

	void OnModuleUnload(User *u, Module *m) override
	{
		OnModuleUnload();
		Module::OnModuleUnload(u, m);
	}

	void CreateBot()
	{
		if (secureBot)
			return;

		secureBot = BotInfo::Find("SeCuRe");
		if (!secureBot)
		{
			// Create the bot in code, core-style, with all required fields and modes
			secureBot = new BotInfo("SeCuRe", "SeCuRe", "network.services", "SeCuRe Servers", "+oSiI");
			Log(LOG_NORMAL, "m_secure") << "Created SeCuRe bot (core style).";
		}
		// Make the bot join the log channel if configured
		if (!log_channel_name.empty()) {
			bool chan_created = false;
			Channel *logchan = Channel::FindOrCreate(log_channel_name, chan_created);
			if (logchan && !logchan->FindUser(secureBot)) {
				secureBot->Join(logchan); // Join as a service bot
				Log(LOG_NORMAL, "m_secure") << "SeCuRe joined log channel: " << log_channel_name;
			}
		}
	}

	// Helper for cURL HTTP GET
	static size_t CurlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
		((std::string*)userp)->append((char*)contents, size * nmemb);
		return size * nmemb;
	}

	// Proxy check logic using proxycheck.io
	bool IsProxyIP(const std::string& ip, ProxyCache& cache, const std::string& api_key) {
		bool cached_result;
		if (cache.get(ip, cached_result))
			return cached_result;

		std::string url = "https://proxycheck.io/v2/" + ip + "?key=" + api_key + "&vpn=1&asn=1&node=1&inf=1";
		CURL* curl = curl_easy_init();
		if (!curl) return false;
		std::string response;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		CURLcode res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		if (res != CURLE_OK) return false;

		// Parse JSON response robustly
		try {
			auto json = nlohmann::json::parse(response);
			if (json.contains(ip) && json[ip].contains("proxy")) {
				bool is_proxy = json[ip]["proxy"] == "yes";
				cache.set(ip, is_proxy);
				return is_proxy;
			}
		} catch (...) {
			// Fallback to string search if JSON parsing fails
			bool is_proxy = response.find("\"proxy\":\"yes\"") != std::string::npos;
			cache.set(ip, is_proxy);
			return is_proxy;
		}
		cache.set(ip, false);
		return false;
	}

	// In OnUserConnect, check if secureBot is valid before using it
	void OnUserConnect(User *user, bool &exempt) override
	{
		if (exempt || user->Quitting() || !Me->IsSynced() || !user->server->IsSynced())
			return;
		// Whitelist check
		std::string servername = user->server ? user->server->GetName().str() : "";
		if (user->server && whitelisted_servers.count(servername))
			return;
		// Wildcard check
		if (wildcard_server.size() > 1 && wildcard_server[0] == '*' && wildcard_server[1] == '.') {
			std::string suffix = wildcard_server.substr(1); // e.g. ".uin"
			if (servername.length() >= suffix.length() && servername.compare(servername.length() - suffix.length(), suffix.length(), suffix) == 0)
				return;
		}
		if (!user->ip.valid() || user->ip.sa.sa_family != AF_INET)
			return;
		std::string ip = user->ip.addr().str();
		if (IsProxyIP(ip, proxyCache, proxycheck_api_key)) {
			if (secureBot)
				user->SendMessage(secureBot, "You are connecting from a detected proxy. Please reconnect without a proxy.");
			user->Kill(Me, "Proxy detected by SeCuRe");

			// Logging to channel if configured and bot is present
			if (secureBot && !log_channel_name.empty()) {
				Channel *logchan = Channel::Find(log_channel_name);
				if (logchan && logchan->FindUser(secureBot)) {
					MessageSource src(secureBot);
					Anope::string msg = "Killed proxy user: " + user->nick + " [" + Anope::string(ip.c_str()) + "]";
					IRCD->SendPrivmsg(src, logchan->name, msg.c_str());
				}
			}
		}
	}
};

MODULE_INIT(SeCuReModule)
