
#include "module.h"
#include "uplink.h"

// InspIRCd-only OperServ wrapper for the /FILTER command (module "filter").
//
// Example Anope config:
//   module { name = "os_spamfilter" }
//   command { service = "OperServ"; name = "SPAMFILTER"; command = "operserv/spamfilter"; permission = "operserv/spamfilter"; }
//   spamfilter {
//       method = "encap"; // encap | direct
//       default_action = "gline";
//       default_flags = "nop";
//       default_duration = "1h";
//       default_reason = "Spam is not allowed";
//   }

namespace
{
	static bool IsInspIRCdProtocol()
	{
		// Prefer checking the loaded protocol module.
		if (ModuleManager::FindModule("inspircd"))
			return true;

		// Fallback to protocol name.
		return IRCD && IRCD->GetProtocolName().find_ci("inspircd") != Anope::string::npos;
	}

	static Anope::string JoinParams(const std::vector<Anope::string> &params, size_t start)
	{
		Anope::string out;
		for (size_t i = start; i < params.size(); ++i)
		{
			if (!out.empty())
				out += " ";
			out += params[i];
		}
		return out;
	}

	static bool NeedsDuration(const Anope::string &action)
	{
		return action.equals_ci("gline") || action.equals_ci("zline") || action.equals_ci("shun");
	}

	static bool LooksLikeGlob(const Anope::string& pattern)
	{
		// Be conservative: only auto-treat as glob when it contains glob tokens and
		// doesn't contain obvious regex metacharacters.
		if (pattern.find('*') == Anope::string::npos && pattern.find('?') == Anope::string::npos)
			return false;

		return pattern.find_first_of("\\()[]{}|+^$.") == Anope::string::npos;
	}

	static Anope::string GlobToRegex(const Anope::string& glob)
	{
		// Convert a simple glob to an ECMA-style regex.
		// NOTE: We intentionally do not add ^/$ anchors because InspIRCd's regex engines
		// generally search within a string (and users often want substring matches).
		Anope::string out;
		bool escaping = false;
		for (const auto ch : glob)
		{
			if (escaping)
			{
				// Force literal.
				switch (ch)
				{
					case '.': case '\\': case '+': case '(': case ')': case '[': case ']':
					case '{': case '}': case '^': case '$': case '|': case '*': case '?':
						out += "\\";
						break;
					default:
						break;
				}
				out += ch;
				escaping = false;
				continue;
			}

			if (ch == '\\')
			{
				escaping = true;
				continue;
			}

			switch (ch)
			{
				case '*': out += ".*"; break;
				case '?': out += "."; break;
				case '.': case '+': case '(': case ')': case '[': case ']': case '{': case '}':
				case '^': case '$': case '|':
					out += "\\";
					out += ch;
					break;
				default:
					out += ch;
					break;
			}
		}

		// Trailing backslash: treat as a literal backslash.
		if (escaping)
			out += "\\\\";

		return out;
	}

	static unsigned long ParseDurationSeconds(const Anope::string& duration)
	{
		if (duration.empty())
			return 0;

		time_t seconds = Anope::DoTime(duration);
		if (seconds <= 0)
			return 0;
		return static_cast<unsigned long>(seconds);
	}

	static Anope::string EncodeFilterMetadataValue(const Anope::string& pattern, const Anope::string& action,
		const Anope::string& flags, unsigned long duration_seconds, const Anope::string& reason)
	{
		// Matches InspIRCd m_filter.cpp EncodeFilter():
		//   <pattern> <action> <flags> <duration> :<reason>
		// With spaces in the pattern escaped to \x07.
		Anope::string freeform = pattern;
		for (auto& chr : freeform)
		{
			if (chr == ' ')
				chr = '\x07';
		}

		Anope::string out;
		out += freeform;
		out += " ";
		out += action;
		out += " ";
		out += flags.empty() ? "-" : flags;
		out += " ";
		out += Anope::ToString(duration_seconds);
		out += " :";
		out += reason;
		return out;
	}
}

class CommandOSSpamfilter final
	: public Command
{
	Anope::string method;
	Anope::string pattern_type;
	Anope::string default_action;
	Anope::string default_flags;
	Anope::string default_duration;
	Anope::string default_reason;

	void LoadDefaults()
	{
		// Anope 2.1 config style: module settings live inside the module{} block.
		// We also keep compatibility with an older top-level spamfilter{} block.
		Configuration::Block legacy = Config->GetBlock("spamfilter");
		method = legacy.Get<Anope::string>("method", "metadata");
		default_action = legacy.Get<Anope::string>("default_action", "gline");
		default_flags = legacy.Get<Anope::string>("default_flags", "nop");
		default_duration = legacy.Get<Anope::string>("default_duration", "1h");
		default_reason = legacy.Get<Anope::string>("default_reason", "Spam is not allowed");

		Configuration::Block blk = Config->GetModule("os_spamfilter");
		method = blk.Get<Anope::string>("method", method);
		pattern_type = blk.Get<Anope::string>("pattern_type", "auto");
		default_action = blk.Get<Anope::string>("default_action", default_action);
		default_flags = blk.Get<Anope::string>("default_flags", default_flags);
		default_duration = blk.Get<Anope::string>("default_duration", default_duration);
		default_reason = blk.Get<Anope::string>("default_reason", default_reason);
	}

	void SendFilter(CommandSource &source, const std::vector<Anope::string> &args)
	{
		// InspIRCd v4 m_filter does not allow remote servers to execute /FILTER via ENCAP
		// because the command requires an oper user. Instead it accepts new filters via
		// broadcast METADATA with key "filter".
		if (method.equals_ci("metadata"))
		{
			if (args.size() == 1)
			{
				// There is no supported S2S delete in m_filter via metadata.
				// The /FILTER delete form requires an oper user.
				Uplink::SendInternal({}, Me, "FILTER", args);
			}
			else if (args.size() >= 4)
			{
				const Anope::string& pattern = args[0];
				const Anope::string& action = args[1];
				const Anope::string& flags = args[2];

				Anope::string wire_pattern = pattern;
				if (pattern_type.equals_ci("glob") || (pattern_type.equals_ci("auto") && LooksLikeGlob(pattern)))
					wire_pattern = GlobToRegex(pattern);

				unsigned long duration_seconds = 0;
				Anope::string reason;
				if (NeedsDuration(action))
				{
					duration_seconds = ParseDurationSeconds(args[3]);
					reason = args.size() >= 5 ? args[4] : default_reason;
				}
				else
				{
					reason = args[3];
				}

				if (reason.empty())
					reason = default_reason;

				Anope::string encoded = EncodeFilterMetadataValue(wire_pattern, action.lower(), flags, duration_seconds, reason);
				Uplink::SendInternal({}, Me, "METADATA", { "*", "filter", encoded });
			}
			else
			{
				Uplink::SendInternal({}, Me, "FILTER", args);
			}
		}
		else if (method.equals_ci("encap"))
		{
			std::vector<Anope::string> encap;
			encap.reserve(args.size() + 2);
			encap.emplace_back("*");
			encap.emplace_back("FILTER");
			encap.insert(encap.end(), args.begin(), args.end());
			Uplink::SendInternal({}, Me, "ENCAP", encap);
		}
		else
		{
			Uplink::SendInternal({}, Me, "FILTER", args);
		}

		Log(LOG_COMMAND, source, this);
	}

public:
	CommandOSSpamfilter(Module *creator)
		: Command(creator, "operserv/spamfilter", 1, -1)
	{
		this->SetDesc(_("Manage InspIRCd /FILTER entries"));
		this->SetSyntax(_("ADD \037pattern\037 [\037action\037 [\037flags\037 [\037duration\037]]] [\037reason...\037]"));
		this->SetSyntax(_("DEL \037pattern\037"));
		this->SetSyntax(_("INFO"));

		this->RequireUser(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		if (!source.HasPriv("operserv/spamfilter"))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		if (!IsInspIRCdProtocol())
		{
			source.Reply(_("This module only supports InspIRCd."));
			return;
		}

		LoadDefaults();

		const Anope::string sub = params[0];
		if (sub.equals_ci("INFO"))
		{
			source.Reply(_("InspIRCd filter module wrapper."));
			source.Reply(_("This sends /FILTER to the IRCd."));
			source.Reply(_("Tip: Use /STATS s on the IRCd to list filters."));
			source.Reply(_("Defaults: action=%s flags=%s duration=%s reason=%s"),
				default_action.c_str(), default_flags.c_str(), default_duration.c_str(), default_reason.c_str());
			source.Reply(_("Send method: %s"), method.c_str());
			return;
		}

		if (sub.equals_ci("DEL") || sub.equals_ci("REMOVE"))
		{
			if (params.size() < 2)
			{
				this->OnSyntaxError(source, "DEL");
				return;
			}

			const Anope::string &pattern = params[1];
			SendFilter(source, { pattern });
			source.Reply(_("Requested removal of filter: %s"), pattern.c_str());
			return;
		}

		if (sub.equals_ci("ADD"))
		{
			if (params.size() < 2)
			{
				this->OnSyntaxError(source, "ADD");
				return;
			}

			Anope::string pattern = params[1];
			if (pattern_type.equals_ci("glob") || (pattern_type.equals_ci("auto") && LooksLikeGlob(pattern)))
				pattern = GlobToRegex(pattern);

			Anope::string action = params.size() >= 3 ? params[2] : default_action;
			Anope::string flags = params.size() >= 4 ? params[3] : default_flags;

			std::vector<Anope::string> cmd;
			cmd.reserve(5);
			cmd.emplace_back(pattern);
			cmd.emplace_back(action);
			cmd.emplace_back(flags);

			size_t reason_idx;
			if (NeedsDuration(action))
			{
				Anope::string duration = params.size() >= 5 ? params[4] : default_duration;
				cmd.emplace_back(duration);
				reason_idx = 5;
			}
			else
			{
				reason_idx = 4;
			}

			Anope::string reason = (params.size() > reason_idx) ? JoinParams(params, reason_idx) : default_reason;
			if (reason.empty())
				reason = default_reason;
			cmd.emplace_back(reason);

			SendFilter(source, cmd);
			source.Reply(_("Requested add/update of filter: %s (action=%s flags=%s)"),
				pattern.c_str(), action.c_str(), flags.c_str());
			return;
		}

		this->SendSyntax(source);
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("This is an InspIRCd v4 wrapper around the /FILTER command (m_filter)."));
		source.Reply(_(" "));
		source.Reply(_("Examples:"));
		source.Reply(_("  /msg OperServ SPAMFILTER ADD *spam* kill coP Spam is off-topic"));
		source.Reply(_("  /msg OperServ SPAMFILTER ADD *fluffy?capybara* gline nop 1h Fluffy capybaras are too cute"));
		source.Reply(_("  /msg OperServ SPAMFILTER DEL *spam*"));
		source.Reply(_(" "));
		source.Reply(_("InspIRCd flags: * c n o P p q r (see InspIRCd m_filter docs)."));
		return true;
	}
};

class OSSpamfilter final
	: public Module
{
	CommandOSSpamfilter cmd;

public:
	OSSpamfilter(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, cmd(this)
	{
		if (!IsInspIRCdProtocol())
			Log() << "m_os_spamfilter: InspIRCd protocol not detected; module will be inert.";

		this->SetAuthor("reverse (ported for InspIRCd v4 filter)");
		this->SetVersion("2.1-inspircd4");
	}
};

MODULE_INIT(OSSpamfilter)

