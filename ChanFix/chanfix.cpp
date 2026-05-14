/*
 * ChanFix for Anope 2.1.
 *
 * This module tracks operators in unregistered channels and can attempt to
 * restore +o to likely operators in opless channels. It intentionally skips
 * registered channels using ChanServ's registration list (ChannelInfo::Find).
 */

#include "chanfix.h"

#include <memory>

class CommandChanFix final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFix(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/chanfix", 1, 1)
		, cf(core)
	{
		this->SetDesc("Manually request a chanfix for a channel.");
		this->SetSyntax("<#channel>");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		cf.RequestFix(source, params[0]);
	}

	bool OnHelp(CommandSource& source, const Anope::string&) override
	{
		source.Reply(" ");
		source.Reply("Requests a fix for an unregistered channel.");
		source.Reply("Example: CHANFIX #channel");
		return true;
	}
};

class CommandCSChanFix final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandCSChanFix(Module* creator, ChanFixCore& core)
		: Command(creator, "chanserv/chanfix", 1, 1)
		, cf(core)
	{
		this->SetDesc("Request ChanFix for an unregistered channel.");
		this->SetSyntax("<#channel>");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		cf.RequestFixFromChanServ(source, params[0]);
	}

	bool OnHelp(CommandSource& source, const Anope::string&) override
	{
		source.Reply(" ");
		source.Reply("Requests a fix for an unregistered channel.");
		source.Reply("You must be opped in the channel or have chanfix/admin.");
		source.Reply("Example: CHANFIX #channel");
		return true;
	}
};

class CommandChanFixScores final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFixScores(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/scores", 1, 2)
		, cf(core)
	{
		this->SetDesc("List chanfix scores for a channel.");
		this->SetSyntax("<#channel> [count]");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		unsigned int count = 20;
		if (params.size() >= 2 && !params[1].empty())
		{
			try { count = Anope::Convert<unsigned int>(params[1], 20); } catch (...) { count = 20; }
		}
		cf.ShowScores(source, params[0], count);
	}
};

class CommandChanFixInfo final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFixInfo(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/info", 1, 1)
		, cf(core)
	{
		this->SetDesc("Show chanfix info for a channel.");
		this->SetSyntax("<#channel>");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		cf.ShowInfo(source, params[0]);
	}
};

class CommandChanFixList final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFixList(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/list", 0, 1)
		, cf(core)
	{
		this->SetDesc("List channels with chanfix records.");
		this->SetSyntax("[pattern]");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		cf.ListChannels(source, params.empty() ? "" : params[0]);
	}
};

class CommandChanFixMark final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFixMark(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/mark", 2, 3)
		, cf(core)
	{
		this->SetDesc("Mark a channel with a note.");
		this->SetSyntax("<#channel> <ON|OFF> [note]");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		const Anope::string& channel = params[0];
		const Anope::string& action = params[1];
		const Anope::string note = (params.size() >= 3) ? params[2] : "";

		if (action.equals_ci("ON"))
		{
			if (note.empty())
			{
				source.Reply("Usage: MARK <#channel> ON <note>");
				return;
			}
			cf.SetMark(source, channel, true, note);
			return;
		}
		if (action.equals_ci("OFF"))
		{
			cf.SetMark(source, channel, false, "");
			return;
		}
		source.Reply("Usage: MARK <#channel> <ON|OFF> [note]");
	}
};

class CommandChanFixNoFix final
	: public Command
{
	ChanFixCore& cf;

public:
	CommandChanFixNoFix(Module* creator, ChanFixCore& core)
		: Command(creator, "chanfix/nofix", 2, 3)
		, cf(core)
	{
		this->SetDesc("Enable/disable NOFIX for a channel.");
		this->SetSyntax("<#channel> <ON|OFF> [reason]");
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		const Anope::string& channel = params[0];
		const Anope::string& action = params[1];
		const Anope::string reason = (params.size() >= 3) ? params[2] : "";

		if (action.equals_ci("ON"))
		{
			if (reason.empty())
			{
				source.Reply("Usage: NOFIX <#channel> ON <reason>");
				return;
			}
			cf.SetNoFix(source, channel, true, reason);
			return;
		}
		if (action.equals_ci("OFF"))
		{
			cf.SetNoFix(source, channel, false, "");
			return;
		}
		source.Reply("Usage: NOFIX <#channel> <ON|OFF> [reason]");
	}
};

class ChanFixTimer final
	: public Timer
{
public:
	enum class Kind
	{
		Gather,
		Expire,
		Autofix,
	};

	ChanFixTimer(Module* owner, ChanFixCore& core, time_t seconds, Kind kind)
		: Timer(owner, seconds)
		, cf(core)
		, k(kind)
	{
	}

	bool Tick() override
	{
		switch (this->k)
		{
			case Kind::Gather:
				cf.GatherTick();
				break;
			case Kind::Expire:
				cf.ExpireTick();
				break;
			case Kind::Autofix:
				cf.AutoFixTick();
				break;
		}
		return true;
	}

private:
	ChanFixCore& cf;
	Kind k;
};

class ChanFix final
	: public Module
{
	ChanFixChannelDataType chanfixdata_type;
	ChanFixCore core;

	CommandChanFix cmd_chanfix;
	CommandCSChanFix cmd_cs_chanfix;
	CommandChanFixScores cmd_scores;
	CommandChanFixInfo cmd_info;
	CommandChanFixList cmd_list;
	CommandChanFixMark cmd_mark;
	CommandChanFixNoFix cmd_nofix;

	std::unique_ptr<ChanFixTimer> gather;
	std::unique_ptr<ChanFixTimer> expire;
	std::unique_ptr<ChanFixTimer> autofix;

	void RecreateTimers()
	{
		this->gather.reset();
		this->expire.reset();
		this->autofix.reset();

		if (this->core.GetGatherInterval() > 0)
			this->gather = std::make_unique<ChanFixTimer>(this, this->core, this->core.GetGatherInterval(), ChanFixTimer::Kind::Gather);
		if (this->core.GetExpireInterval() > 0)
			this->expire = std::make_unique<ChanFixTimer>(this, this->core, this->core.GetExpireInterval(), ChanFixTimer::Kind::Expire);
		if (this->core.GetAutofixInterval() > 0)
			this->autofix = std::make_unique<ChanFixTimer>(this, this->core, this->core.GetAutofixInterval(), ChanFixTimer::Kind::Autofix);
	}

public:
	ChanFix(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, VENDOR)
		, chanfixdata_type(this)
		, core(this)
		, cmd_chanfix(this, core)
		, cmd_cs_chanfix(this, core)
		, cmd_scores(this, core)
		, cmd_info(this, core)
		, cmd_list(this, core)
		, cmd_mark(this, core)
		, cmd_nofix(this, core)
	{
	}

	void OnReload(Configuration::Conf& conf) override
	{
		this->core.OnReload(conf);
		this->RecreateTimers();
	}

	void OnModuleLoad(User*, Module* m) override
	{
		if (m == this)
		{
			this->core.LegacyImportIfNeeded();
			if (this->core.LegacyImportNeedsSave())
				this->core.ScheduleDBSave();
		}
	}
};

MODULE_INIT(ChanFix)
