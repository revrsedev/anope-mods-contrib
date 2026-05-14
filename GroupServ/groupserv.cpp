/*
 * (C) 2026 reverse Juean Chevronnet
 * Contact me at mike.chevronnet@gmail.com
 * IRC: irc.irc4fun.net Port:+6697 (tls)
 * Channel: #development
 *
 * GroupServ module created by reverse for Anope 2.1
 * - Account groups: REGISTER/INFO/LIST
 * - Membership: JOIN, INVITE
 * - Access control: FLAGS (per-member permissions)
 * - Settings: SET (OPEN/PUBLIC/JOINFLAGS + metadata)
 * - Persistence: flatfile database in data/groupserv.db (atomic .tmp + rename)
 *
 * Notes:
 * - Group names are like !group
 * - Access flags here are GroupServ-specific (NOT IRC user modes)
 *
 * Example configuration:
 *
 * service
 * {
 *   nick = "GroupServ"
 *   user = "GroupServ"
 *   host = "chaat.services"
 *   gecos = "Group Service"
 *   channels = "@#services"  # optional
 * }
 *
 * module
 * {
 *   name = "groupserv"
 *   client = "GroupServ"
 *
 *   # How GroupServ replies to users: "notice" or "privmsg"
 *   reply_method = "notice"
 *
 *   # Privileges
 *   admin_priv = "groupserv/admin"    # FDROP/FFLAGS
 *   auspex_priv = "groupserv/auspex"  # view/list any group
 *   exceed_priv = "groupserv/exceed"  # bypass limits
 *
 *   # Limits
 *   maxgroups = 5
 *   maxgroupacs = 0
 *
 *   # Open groups
 *   enable_open_groups = yes
 *
 *   # Default flags granted when a user JOINs an open group.
 *   # These are GroupServ access flags (NOT IRC user modes).
 *   # Accepts: +A +I, +ACLVIEW +INVITE, or compact +AI.
 *   default_joinflags = "+A"
 *
 *   # Per-group VHOST approval:
 *   # - SET <!group> VHOSTAUTO ON  => auto-approve vhost
 *   # - SET <!group> VHOSTAUTO OFF => request via HostServ (default)
 *
 *   # Auto-save interval in seconds (0 disables periodic autosave)
 *   save_interval = 600
 * }
 *
 * command { service = "GroupServ"; name = "HELP"; command = "generic/help"; }
 * command { service = "GroupServ"; name = "REGISTER"; command = "groupserv/register"; }
 * command { service = "GroupServ"; name = "DROP"; command = "groupserv/drop"; }
 * command { service = "GroupServ"; name = "LIST"; command = "groupserv/list"; }
 * command { service = "GroupServ"; name = "INFO"; command = "groupserv/info"; }
 * command { service = "GroupServ"; name = "JOIN"; command = "groupserv/join"; }
 * command { service = "GroupServ"; name = "INVITE"; command = "groupserv/invite"; }
 * command { service = "GroupServ"; name = "FLAGS"; command = "groupserv/flags"; }
 * command { service = "GroupServ"; name = "SET"; command = "groupserv/set"; }
 * command { service = "GroupServ"; name = "FDROP"; command = "groupserv/fdrop"; hide = true; }
 * command { service = "GroupServ"; name = "FFLAGS"; command = "groupserv/fflags"; hide = true; }
 */

#include "groupserv.h"

#include "language.h"
#include "commands.h"

#include <algorithm>
#include <memory>
#include <set>

namespace
{
	bool ParseHostMask(const Anope::string& rawhostmask, Anope::string& user, Anope::string& host)
	{
		Anope::string raw = rawhostmask;
		raw.trim();
		if (raw.empty())
			return false;
		if (raw.find(' ') != Anope::string::npos)
			return false;

		size_t a = raw.find('@');
		if (a == Anope::string::npos)
			host = raw;
		else
		{
			user = raw.substr(0, a);
			host = raw.substr(a + 1);
		}
		return !host.empty();
	}

	bool HasChanServSetAccess(CommandSource& source, ChannelInfo* ci)
	{
		return (ci && (source.AccessFor(ci).HasPriv("SET") || source.HasPriv("chanserv/administration")));
	}

	bool IsGroupTargetMask(const Anope::string& mask)
	{
		if (mask.empty() || mask[0] != '!')
			return false;
		// Avoid treating hostmasks as groups.
		if (mask.find_first_of("*@?") != Anope::string::npos)
			return false;
		if (mask.find('@') != Anope::string::npos)
			return false;
		// Avoid treating channels as groups.
		if (IRCD->IsChannelValid(mask))
			return false;
		return true;
	}

	bool GroupGrantsChanPrivRecurse(GroupServCore& gs, const NickCore* nc, const ChannelInfo* ci, const Anope::string& priv,
		unsigned depth, std::set<const ChannelInfo*>& seen)
	{
		if (!ci || !nc)
			return false;
		if (depth > ChanAccess::MAX_DEPTH)
			return false;
		if (seen.count(ci))
			return false;
		seen.insert(ci);

		for (unsigned i = 0; i < ci->GetAccessCount(); ++i)
		{
			ChanAccess* a = ci->GetAccess(i);
			if (!a)
				continue;

			const auto& mask = a->Mask();
			if (IsGroupTargetMask(mask) && gs.DoesGroupExist(mask) && gs.HasGroupAccess(mask, nc, GSAccessFlags::CHANACCESS))
			{
				if (a->HasPriv(priv))
					return true;
			}

			if (IRCD->IsChannelValid(mask))
			{
				ChannelInfo* next = ChannelInfo::Find(mask);
				if (GroupGrantsChanPrivRecurse(gs, nc, next, priv, depth + 1, seen))
					return true;
			}
		}

		return false;
	}

	bool GroupGrantsChanPriv(GroupServCore& gs, const AccessGroup* group, const Anope::string& priv)
	{
		if (!group || !group->ci || !group->nc)
			return false;
		std::set<const ChannelInfo*> seen;
		return GroupGrantsChanPrivRecurse(gs, group->nc, group->ci, priv, 0, seen);
	}
}

namespace
{
	struct GSChanAccessDataType final
		: Serialize::Type
	{
		ExtensibleItem<GSChanAccessData>& item;

		explicit GSChanAccessDataType(ExtensibleItem<GSChanAccessData>& it)
			: Serialize::Type("GSChanAccessData")
			, item(it)
		{
		}

		void Serialize(Serializable* obj, Serialize::Data& data) const override
		{
			const auto* d = static_cast<const GSChanAccessData*>(obj);
			data.Store("ci", d->object);
			data.Store("group", d->group);
			data.Store("group_only", d->group_only ? "1" : "0");
		}

		Serializable* Unserialize(Serializable* obj, Serialize::Data& data) const override
		{
			Anope::string sci, sgroup, sonly;
			data.TryLoad("ci", sci);
			data.TryLoad("group", sgroup);
			data.TryLoad("group_only", sonly);

			ChannelInfo* ci = ChannelInfo::Find(sci);
			if (!ci)
				return nullptr;

			const bool only = (sonly == "1" || sonly.equals_ci("true") || sonly.equals_ci("yes") || sonly.equals_ci("on"));

			if (obj)
			{
				auto* d = anope_dynamic_static_cast<GSChanAccessData*>(obj);
				d->object = ci->name;
				d->group = sgroup;
				d->group_only = only;
				return d;
			}

			return this->item.Set(ci, GSChanAccessData(ci, sgroup, only));
		}
	};
}

class CommandCSSetGroup final
	: public Command
{
	GroupServCore& gs;
	ExtensibleItem<GSChanAccessData>& item;

public:
	CommandCSSetGroup(Module* creator, GroupServCore& core, ExtensibleItem<GSChanAccessData>& it)
		: Command(creator, "chanserv/set/group", 1, 2)
		, gs(core)
		, item(it)
	{
		this->SetDesc(_("Associate a registered channel with a GroupServ group."));
		this->SetSyntax(_("\037channel\037 [\037!group|OFF\037]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		if (Anope::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		ChannelInfo* ci = ChannelInfo::Find(params[0]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		if (!HasChanServSetAccess(source, ci) && source.permission.empty())
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		if (params.size() == 1)
		{
			auto* d = this->item.Get(ci);
			if (!d || d->group.empty())
				source.Reply(_("Group restriction for %s is not set."), ci->name.c_str());
			else
				source.Reply(_("Group restriction for %s is %s (%s)."), ci->name.c_str(), d->group.c_str(), d->group_only ? "GROUPONLY" : "not group-only");
			return;
		}

		const auto& val = params[1];
		if (val.equals_ci("OFF"))
		{
			this->item.Unset(ci);
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to unset GROUP";
			source.Reply(CHAN_SETTING_UNSET, "GROUP", ci->name.c_str());
			return;
		}

		if (!this->gs.DoesGroupExist(val))
		{
			source.Reply(_("Group %s does not exist."), val.c_str());
			return;
		}

		bool only = false;
		if (auto* cur = this->item.Get(ci))
			only = cur->group_only;
		else
			only = true; // default to enforcement when a group is set

		this->item.Set(ci, GSChanAccessData(ci, val, only));
		Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to set GROUP to " << val;
		source.Reply(CHAN_SETTING_CHANGED, "GROUP", ci->name.c_str(), val.c_str());
	}
};

class CommandCSSetGroupOnly final
	: public Command
{
	GroupServCore& gs;
	ExtensibleItem<GSChanAccessData>& item;

public:
	CommandCSSetGroupOnly(Module* creator, GroupServCore& core, ExtensibleItem<GSChanAccessData>& it)
		: Command(creator, "chanserv/set/grouponly", 2, 2)
		, gs(core)
		, item(it)
	{
		this->SetDesc(_("Require GroupServ group membership to remain in the channel."));
		this->SetSyntax(_("\037channel\037 <ON|OFF>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		if (Anope::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		ChannelInfo* ci = ChannelInfo::Find(params[0]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		if (!HasChanServSetAccess(source, ci) && source.permission.empty())
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		const auto setting = params[1].upper();
		if (setting != "ON" && setting != "OFF")
		{
			source.Reply(_("Syntax: %s %s"), source.command.c_str(), "\037channel\037 <ON|OFF>");
			return;
		}

		auto* cur = this->item.Get(ci);
		const bool enable = (setting == "ON");

		if (enable)
		{
			if (!cur || cur->group.empty())
			{
				source.Reply(_("You must set GROUP first (use: CHANSERV SET %s GROUP <!group>)."), ci->name.c_str());
				return;
			}

			if (!this->gs.DoesGroupExist(cur->group))
			{
				source.Reply(_("Group %s does not exist."), cur->group.c_str());
				return;
			}

			this->item.Set(ci, GSChanAccessData(ci, cur->group, true));
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to enable GROUPONLY";
			source.Reply(CHAN_SETTING_CHANGED, "GROUPONLY", ci->name.c_str(), "ON");
		}
		else
		{
			if (!cur)
			{
				source.Reply(_("GROUPONLY for %s is already OFF."), ci->name.c_str());
				return;
			}
			this->item.Set(ci, GSChanAccessData(ci, cur->group, false));
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to disable GROUPONLY";
			source.Reply(CHAN_SETTING_CHANGED, "GROUPONLY", ci->name.c_str(), "OFF");
		}
	}
};

namespace
{
	void ReplySyntaxAndMoreInfo(GroupServCore& gs, CommandSource& source, const Anope::string& syntax)
	{
		if (syntax.empty())
			gs.Reply(source, Anope::Format("Syntax: %s", source.command.c_str()));
		else
			gs.Reply(source, Anope::Format("Syntax: %s %s", source.command.c_str(), syntax.c_str()));

		if (!source.service)
			return;

		auto it = std::find_if(source.service->commands.begin(), source.service->commands.end(), [](const auto& cmd)
		{
			return cmd.second.name == "generic/help";
		});
		if (it != source.service->commands.end())
			gs.Reply(source, Anope::Format(MORE_INFO, source.service->GetQueryCommand("generic/help", source.command).c_str()));
	}
}

class CommandGroupServRegister final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServRegister(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/register", 1, 1)
		, gs(core)
	{
		this->SetDesc(_("Register a group."));
		this->SetSyntax(_("<!group>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.RegisterGroup(source, params[0]);
	}
};

class CommandGroupServDrop final
	: public Command
{
	GroupServCore& gs;
	bool force;

public:
	CommandGroupServDrop(Module* creator, GroupServCore& core, const Anope::string& sname, bool f)
		: Command(creator, sname, 1, 2)
		, gs(core)
		, force(f)
	{
		this->SetDesc(_("Drop a group."));
		this->SetSyntax(_("<!group> [key]"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> [key]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.DropGroup(source, params[0], params.size() >= 2 ? params[1] : "", this->force);
	}
};

class CommandGroupServInfo final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServInfo(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/info", 1, 1)
		, gs(core)
	{
		this->SetDesc(_("Show information about a group."));
		this->SetSyntax(_("<!group>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.ShowInfo(source, params[0]);
	}
};

class CommandGroupServList final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServList(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/list", 0, 1)
		, gs(core)
	{
		this->SetDesc(_("List groups."));
		this->SetSyntax(_("[pattern]"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("[pattern]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.ListGroups(source, params.empty() ? "" : params[0]);
	}
};

class CommandGroupServJoin final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServJoin(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/join", 1, 1)
		, gs(core)
	{
		this->SetDesc(_("Join a group."));
		this->SetSyntax(_("<!group>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.JoinGroup(source, params[0]);
	}
};

class CommandGroupServInvite final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServInvite(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/invite", 2, 2)
		, gs(core)
	{
		this->SetDesc(_("Invite an account to a group."));
		this->SetSyntax(_("<!group> <account>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> <account>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.InviteToGroup(source, params[0], params[1]);
	}
};

class CommandGroupServListChans final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServListChans(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/listchans", 1, 1)
		, gs(core)
	{
		this->SetDesc(_("Lists channels associated with a group."));
		this->SetSyntax(_("<!group>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.ListChans(source, params[0]);
	}
};

class CommandGroupServVHost final
	: public Command
{
	GroupServCore& gs;

	class ForwardReply final
		: public CommandReply
	{
		CommandSource& source;

	public:
		explicit ForwardReply(CommandSource& src)
			: source(src)
		{
		}

		void SendMessage(BotInfo*, const Anope::string& msg) override
		{
			source.Reply("%s", msg.c_str());
		}
	};

	bool RequestVHost(CommandSource& source, const Anope::string& hostmask)
	{
		ServiceReference<Command> requestcmd("Command", "hostserv/request");
		if (!requestcmd)
		{
			this->gs.Reply(source, "HostServ request command is not available.");
			return false;
		}

		BotInfo* bi = nullptr;
		Anope::string cmdname;
		if (!Command::FindFromService("hostserv/request", bi, cmdname) || !bi)
		{
			this->gs.Reply(source, "HostServ is not available.");
			return false;
		}

		CommandInfo* info = bi->GetCommand(cmdname);
		if (!info)
		{
			this->gs.Reply(source, "HostServ request command is not available.");
			return false;
		}

		ForwardReply reply(source);
		CommandSource hs_source(source.GetNick(), source.GetUser(), source.GetAccount(), &reply, bi);
		hs_source.ip = source.ip;

		std::vector<Anope::string> params;
		params.push_back(hostmask);
		requestcmd->Run(hs_source, cmdname, *info, params);
		return true;
	}

	static void SyncAliases(const NickAlias* na)
	{
		if (!na || !na->HasVHost() || !na->nc)
			return;
		for (auto* nick : *na->nc->aliases)
		{
			if (nick && nick != na)
				nick->SetVHost(na->GetVHostIdent(), na->GetVHostHost(), na->GetVHostCreator());
		}
	}

public:
	CommandGroupServVHost(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/vhost", 1, 2)
		, gs(core)
	{
		this->SetDesc(_("Activate or remove a group vhost (requires +v, supports $account/$group)"));
		this->SetSyntax(_("<!group> [OFF]"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> [OFF]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		if (!source.GetAccount())
		{
			this->gs.Reply(source, "You must be identified to use VHOST.");
			return;
		}
		if (!IRCD || !IRCD->CanSetVHost)
		{
			this->gs.Reply(source, "Your IRCd does not support vhosts.");
			return;
		}

		const auto& groupname = params[0];
		if (!this->gs.DoesGroupExist(groupname))
		{
			this->gs.ReplyF(source, "Group %s does not exist.", groupname.c_str());
			return;
		}
		if (!this->gs.HasGroupAccess(groupname, source.GetAccount(), GSAccessFlags::VHOST) && !this->gs.IsAuspex(source))
		{
			this->gs.Reply(source, ACCESS_DENIED);
			return;
		}

		NickAlias* na = NickAlias::Find(source.GetAccount()->display);
		if (!na)
		{
			this->gs.Reply(source, "Your account has no NickAlias.");
			return;
		}

		if (params.size() >= 2 && params[1].equals_ci("OFF"))
		{
			if (!na->HasVHost())
			{
				this->gs.Reply(source, "You do not have a vhost set.");
				return;
			}
			FOREACH_MOD(OnDeleteVHost, (na));
			na->RemoveVHost();
			this->gs.Reply(source, "Your vhost has been removed.");
			return;
		}

		Anope::string gvhost;
		if (!this->gs.GetGroupVHost(groupname, gvhost) || gvhost.empty())
		{
			this->gs.ReplyF(source, "No group vhost is set for %s.", groupname.c_str());
			this->gs.Reply(source, "Set one with: /msg GroupServ SET <!group> VHOST <hostmask>  (supports $account/$group)");
			return;
		}

		Anope::string expanded = gvhost;
		expanded = expanded.replace_all_cs("$account", source.GetAccount()->display);
		Anope::string groupvar = groupname;
		if (!groupvar.empty() && groupvar[0] == '!')
			groupvar = groupvar.substr(1);
		expanded = expanded.replace_all_cs("$group", groupvar);

		Anope::string user, host;
		if (!ParseHostMask(expanded, user, host))
		{
			this->gs.Reply(source, "The group vhost is invalid. Ask a founder to re-set it.");
			return;
		}
		if (!user.empty() && !IRCD->CanSetVIdent)
		{
			this->gs.Reply(source, HOST_NO_VIDENT);
			return;
		}
		if (host.length() > IRCD->MaxHost)
		{
			source.Reply(HOST_SET_VHOST_TOO_LONG, IRCD->MaxHost);
			this->gs.ReplyF(source, "Expanded vhost was: %s", expanded.c_str());
			return;
		}
		if (!IRCD->IsHostValid(host))
		{
			source.Reply(HOST_SET_VHOST_ERROR);
			this->gs.ReplyF(source, "Expanded vhost was: %s", expanded.c_str());
			return;
		}
		if (!user.empty() && !IRCD->IsIdentValid(user))
		{
			source.Reply(HOST_SET_VIDENT_ERROR);
			this->gs.ReplyF(source, "Expanded vhost was: %s", expanded.c_str());
			return;
		}

		const auto hostmask = (!user.empty() ? user + "@" : "") + host;
		GSGroupFlags gflags = GSGroupFlags::NONE;
		const bool autovhost = (this->gs.GetGroupFlags(groupname, gflags) && HasFlag(gflags, GSGroupFlags::VHOSTAUTO));
		if (autovhost)
		{
			na->SetVHost(user, host, source.GetNick());
			SyncAliases(na);
			FOREACH_MOD(OnSetVHost, (na));
			this->gs.ReplyF(source, "Your vhost is now set to %s.", na->GetVHostMask().c_str());
			return;
		}

		if (!RequestVHost(source, hostmask))
			return;
	}
};

class CommandGroupServAccess final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServAccess(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/access", 2, 3)
		, gs(core)
	{
		this->SetDesc(_("Show or diagnose group channel access (+c)"));
		this->SetSyntax(_("<!group> \037#channel\037 [\037priv\037]"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> \037#channel\037 [\037priv\037]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		if (!source.GetAccount())
		{
			this->gs.Reply(source, "You must be identified to use ACCESS.");
			return;
		}

		const auto& groupname = params[0];
		ChannelInfo* ci = ChannelInfo::Find(params[1]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[1].c_str());
			return;
		}

		if (!this->gs.DoesGroupExist(groupname))
		{
			this->gs.ReplyF(source, "Group %s does not exist.", groupname.c_str());
			return;
		}

		if (!this->gs.HasGroupAccess(groupname, source.GetAccount(), GSAccessFlags::CHANACCESS) && !this->gs.IsAuspex(source))
		{
			this->gs.Reply(source, ACCESS_DENIED);
			return;
		}

		std::vector<ChanAccess*> matches;
		for (unsigned i = 0; i < ci->GetAccessCount(); ++i)
		{
			ChanAccess* a = ci->GetAccess(i);
			if (a && a->Mask().equals_ci(groupname))
				matches.push_back(a);
		}

		if (matches.empty())
		{
			this->gs.ReplyF(source, "No ChanServ access entry for %s exists on %s.", groupname.c_str(), ci->name.c_str());
			this->gs.Reply(source, "Add one with: /msg ChanServ FLAGS \037#channel\037 \037!group\037 +<flags>  (or: /msg ChanServ ACCESS \037#channel\037 ADD \037!group\037 <level>)");
			return;
		}

		this->gs.ReplyF(source, "ChanServ access entries on %s for %s:", ci->name.c_str(), groupname.c_str());
		for (auto* a : matches)
		{
			this->gs.ReplyF(source, "- provider=%s data=%s", a->provider ? a->provider->name.c_str() : "(none)", a->AccessSerialize().c_str());
		}

		this->gs.Reply(source, "Note: these entries apply only to members with GroupServ flag +c in the group.");

		if (params.size() >= 3)
		{
			const auto priv = params[2];
			bool via_group = false;
			for (auto* a : matches)
				if (a->HasPriv(priv))
					via_group = true;

			this->gs.ReplyF(source, "Privilege %s via %s: %s", priv.c_str(), groupname.c_str(), via_group ? "YES" : "NO");
			this->gs.ReplyF(source, "Effective privilege %s on %s (all sources): %s", priv.c_str(), ci->name.c_str(), source.AccessFor(ci).HasPriv(priv) ? "YES" : "NO");
		}
	}
};

class CommandGroupServFlags final
	: public Command
{
	GroupServCore& gs;
	bool force;

public:
	CommandGroupServFlags(Module* creator, GroupServCore& core, const Anope::string& sname, bool f)
		: Command(creator, sname, 1, 3)
		, gs(core)
		, force(f)
	{
		this->SetDesc(_("View or modify group access flags."));
		this->SetSyntax(_("<!group>"));
		this->SetSyntax(_("<!group> <account> <flags>"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		if (params.size() == 1)
			this->gs.ShowFlags(source, params[0]);
		else if (params.size() == 3)
			this->gs.SetFlags(source, params[0], params[1], params[2], this->force);
		else
			ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> [account flags]"));
	}
};

class CommandGroupServSet final
	: public Command
{
	GroupServCore& gs;

public:
	CommandGroupServSet(Module* creator, GroupServCore& core)
		: Command(creator, "groupserv/set", 2, 3)
		, gs(core)
	{
		this->SetDesc(_("Set group options."));
		this->SetSyntax(_("<!group> <setting> [value]"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> <setting> [value]"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.SetOption(source, params[0], params[1], params.size() >= 3 ? params[2] : "");
	}
};

class CommandGroupServToggleGroupFlag final
	: public Command
{
	GroupServCore& gs;
	GSGroupFlags flag;

public:
	CommandGroupServToggleGroupFlag(Module* creator, GroupServCore& core, const Anope::string& name, GSGroupFlags f)
		: Command(creator, name, 2, 2)
		, gs(core)
		, flag(f)
	{
		this->SetDesc(_("Toggle a group limit/flag (Services Operator)."));
		this->SetSyntax(_("<!group> <ON|OFF>"));
		this->AllowUnregistered(true);
	}

	void OnSyntaxError(CommandSource& source, const Anope::string&) override
	{
		ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> <ON|OFF>"));
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		const auto val = params[1].upper();
		if (val != "ON" && val != "OFF")
		{
			ReplySyntaxAndMoreInfo(this->gs, source, _("<!group> <ON|OFF>"));
			return;
		}
		const bool enabled = (val == "ON");
		if (this->gs.SetGroupFlag(source, params[0], this->flag, enabled))
			this->gs.ReplyF(source, "%s for %s set to %s.", source.command.c_str(), params[0].c_str(), enabled ? "ON" : "OFF");
	}
};

class CommandMSGroupSend final
	: public Command
{
	GroupServCore& gs;

public:
	CommandMSGroupSend(Module* creator, GroupServCore& core)
		: Command(creator, "memoserv/gsend", 2, 2)
		, gs(core)
	{
		this->SetDesc(_("Send a memo to a GroupServ group"));
		this->SetSyntax(_("<!group> \037memo-text\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.SendMemo(source, params[0], params[1]);
	}
};

class CommandMSGroupList final
	: public Command
{
	GroupServCore& gs;

public:
	CommandMSGroupList(Module* creator, GroupServCore& core)
		: Command(creator, "memoserv/glist", 1, 1)
		, gs(core)
	{
		this->SetDesc(_("List memos for a GroupServ group"));
		this->SetSyntax(_("<!group>"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		this->gs.ListMemos(source, params[0]);
	}
};

static bool TryParseMemoIndex(const Anope::string& in, unsigned& idx)
{
	Anope::string token = in;
	token.trim();

	const auto sp = token.rfind(' ');
	if (sp != Anope::string::npos)
		token = token.substr(sp + 1);

	token.trim();
	if (!token.empty() && token[0] == '#')
		token.erase(0, 1);

	token.trim();
	idx = Anope::Convert(token, 0u);
	return idx > 0;
}

class CommandMSGroupRead final
	: public Command
{
	GroupServCore& gs;

public:
	CommandMSGroupRead(Module* creator, GroupServCore& core)
		: Command(creator, "memoserv/gread", 2, 2)
		, gs(core)
	{
		this->SetDesc(_("Read a memo for a GroupServ group"));
		this->SetSyntax(_("<!group> \037number\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		unsigned idx = 0;
		if (!TryParseMemoIndex(params[1], idx))
		{
			this->gs.Reply(source, "Invalid memo number.");
			return;
		}
		this->gs.ReadMemo(source, params[0], idx);
	}
};

class CommandMSGroupDel final
	: public Command
{
	GroupServCore& gs;

public:
	CommandMSGroupDel(Module* creator, GroupServCore& core)
		: Command(creator, "memoserv/gdel", 2, 2)
		, gs(core)
	{
		this->SetDesc(_("Delete a memo for a GroupServ group"));
		this->SetSyntax(_("<!group> \037number\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) override
	{
		unsigned idx = 0;
		if (!TryParseMemoIndex(params[1], idx))
		{
			this->gs.Reply(source, "Invalid memo number.");
			return;
		}
		this->gs.DelMemo(source, params[0], idx);
	}
};

class GroupServTimer final
	: public Timer
{
	GroupServCore& gs;

public:
	GroupServTimer(Module* owner, GroupServCore& core, time_t seconds)
		: Timer(owner, seconds)
		, gs(core)
	{
	}

	bool Tick() override
	{
		this->gs.SaveDB();
		return true;
	}
};

class GroupServ final
	: public Module
{
	GroupServCore core;
	ExtensibleItem<GSChanAccessData> chanaccess;
	GSChanAccessDataType chanaccess_type;
	CommandCSSetGroup cmd_cs_set_group;
	CommandCSSetGroupOnly cmd_cs_set_grouponly;

	CommandGroupServRegister cmd_register;
	CommandGroupServDrop cmd_drop;
	CommandGroupServDrop cmd_fdrop;
	CommandGroupServInfo cmd_info;
	CommandGroupServList cmd_list;
	CommandGroupServJoin cmd_join;
	CommandGroupServInvite cmd_invite;
	CommandGroupServListChans cmd_listchans;
	CommandGroupServVHost cmd_vhost;
	CommandGroupServAccess cmd_access;
	CommandGroupServFlags cmd_flags;
	CommandGroupServFlags cmd_fflags;
	CommandGroupServSet cmd_set;
	CommandGroupServToggleGroupFlag cmd_acsnolimit;
	CommandGroupServToggleGroupFlag cmd_regnolimit;

	CommandMSGroupSend cmd_ms_gsend;
	CommandMSGroupList cmd_ms_glist;
	CommandMSGroupRead cmd_ms_gread;
	CommandMSGroupDel cmd_ms_gdel;

	std::unique_ptr<GroupServTimer> save;

	void RecreateTimers()
	{
		this->save.reset();
		if (this->core.GetSaveInterval() > 0)
			this->save = std::make_unique<GroupServTimer>(this, this->core, this->core.GetSaveInterval());
	}

public:
	GroupServ(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, VENDOR)
		, core(this)
		, chanaccess(this, "groupserv:chanaccess")
		, chanaccess_type(chanaccess)
		, cmd_cs_set_group(this, core, chanaccess)
		, cmd_cs_set_grouponly(this, core, chanaccess)
		, cmd_register(this, core)
		, cmd_drop(this, core, "groupserv/drop", false)
		, cmd_fdrop(this, core, "groupserv/fdrop", true)
		, cmd_info(this, core)
		, cmd_list(this, core)
		, cmd_join(this, core)
		, cmd_invite(this, core)
		, cmd_listchans(this, core)
		, cmd_vhost(this, core)
		, cmd_access(this, core)
		, cmd_flags(this, core, "groupserv/flags", false)
		, cmd_fflags(this, core, "groupserv/fflags", true)
		, cmd_set(this, core)
		, cmd_acsnolimit(this, core, "groupserv/acsnolimit", GSGroupFlags::ACSNOLIMIT)
		, cmd_regnolimit(this, core, "groupserv/regnolimit", GSGroupFlags::REGNOLIMIT)
		, cmd_ms_gsend(this, core)
		, cmd_ms_glist(this, core)
		, cmd_ms_gread(this, core)
		, cmd_ms_gdel(this, core)
	{
		this->core.SetChanAccessItem(&this->chanaccess);
	}

	EventReturn OnGroupCheckPriv(const AccessGroup* group, const Anope::string& priv) override
	{
		if (GroupGrantsChanPriv(this->core, group, priv))
			return EVENT_ALLOW;
		return EVENT_CONTINUE;
	}

	~GroupServ() override
	{
		// Persist serialized channel extensions (GROUP/GROUPONLY) across MODRELOAD.
		// This runs before member destructors, so the extension data still exists.
		this->core.SaveDB();
		Anope::SaveDatabases();
	}

	void OnJoinChannel(User* user, Channel* c) override
	{
		if (!c || !c->ci || !user || !user->server || !user->server->IsSynced() || user->server == Me)
			return;

		auto* d = this->chanaccess.Get(c->ci);
		if (!d || !d->group_only || d->group.empty())
			return;

		NickCore* nc = user->Account();
		if (nc && nc->IsServicesOper() && nc->o && nc->o->ot && (nc->o->ot->HasPriv("chanserv/administration") || nc->o->ot->HasPriv("groupserv/admin")))
			return;

		if (this->core.IsMemberOfGroup(d->group, nc))
			return;

		c->Kick(NULL, user, "You must be a member of %s to join %s.", d->group.c_str(), c->name.c_str());
	}

	void OnReload(Configuration::Conf& conf) override
	{
		this->core.OnReload(conf);
		this->RecreateTimers();
	}

	void OnNickInfo(CommandSource& source, NickAlias* na, InfoFormatter& info, bool show_hidden) override
	{
		if (!na || !na->nc)
			return;

		std::vector<Anope::string> groups;
		this->core.GetGroupsForAccount(na->nc, groups, show_hidden);
		if (groups.empty())
			return;

		std::sort(groups.begin(), groups.end());
		Anope::string out;
		for (const auto& g : groups)
		{
			if (!out.empty())
				out += ",";
			out += g;
		}
		info["GroupServ"] = out;
	}

	void OnChanInfo(CommandSource& source, ChannelInfo* ci, InfoFormatter& info, bool show_hidden) override
	{
		if (!ci)
			return;

		auto* d = this->chanaccess.Get(ci);
		if (!d || d->group.empty())
			return;

		GSGroupFlags gflags = GSGroupFlags::NONE;
		if (!this->core.GetGroupFlags(d->group, gflags))
		{
			// Only show missing associations to users who can already see hidden details.
			if (show_hidden)
				info[_("GroupServ")] = d->group + " (missing)";
			return;
		}

		// Mirror NickServ INFO behaviour: only show non-public groups to users who can see hidden details.
		if (!show_hidden && !HasFlag(gflags, GSGroupFlags::PUBLIC))
			return;

		info[_("GroupServ")] = d->group;
	}
};

MODULE_INIT(GroupServ)
