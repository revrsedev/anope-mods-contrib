/*
 * (C) 2025 reverse Juean Chevronnet
 * Contact me at mike.chevronnet@gmail.com
 * IRC: irc.irc4fun.net Port:+6697 (tls)
 * Salon: #development
 *
 * Module m_memo_chanaccess created by reverse to send memos on chanaccess changes
 *
 * module { name = "m_memo_chanaccess" }
 * 
 * MemoServ: [NOTICE] You have 1 new memo.
 * MemoServ: [NOTICE] Memo 1 from tChatCop (Fri Jan  9 12:49:53 2026 (37 seconds ago)).
 * MemoServ: [NOTICE] To delete, type: /msg MemoServ DEL 1
 * MemoServ: [NOTICE] You have been added to the access list for #!accueil by reverse (access: 5).
 *
 * Configuration options for the m_memo_chanaccess
 * 
 * module
 * {
 *    name = "m_memo_chanaccess"
 *
 *    # Use MemoServ (memos)
 *    notify_access_add = yes
 *    notify_access_del = yes
 *    notify_founder_change = yes
 *    notify_successor_change = yes
 *
 *   # Send email — uses Anope’s mail system (same as NickServ’s email features)
 *    email_access_add = no
 *    email_access_del = no
 *    email_founder_change = no
 *    email_successor_change = no
 *
 *   # Mail templates in the global mail block (supports HTML when mail:content_type is text/html)
 *   #  chanaccess_access_subject / chanaccess_access_message
 *   #  chanaccess_access_del_subject / chanaccess_access_del_message
 *   #  chanaccess_founder_subject / chanaccess_founder_message
 *   #  chanaccess_successor_subject / chanaccess_successor_message
 *   # Available tokens:
 *   #  {channel} {actor} {target} {access} {network} {account} {mask} {timestamp}
 *
 *   # If access is added via a mask (e.g. nick!ident@host) and not a registered account,
 *   # the module can't memo/email the target. When enabled, it replies to the command source.
 *    notice_unregistered_access_add = no
 *
 *   # If access is added via a mask (including *!*@*) and the channel currently exists,
 *   # notify matching online users in the channel.
 *    notice_mask_access_add = no
 *
 *   # If the added account is currently online/identified, send them a notice/privmsg too.
 *   # (Uses the same delivery method as other service messages: NOTICE vs PRIVMSG depends on settings.)
 *    notice_online_access_add = no
 *
 *   # If "no", don’t notify when you change your own access/founder/successor
 *    notify_self = no
 *
 *    # Optional: force memo sender nick (otherwise uses WhoSends()/service/ChanServ)
 *    sender = "ChanServ"
 * }
 * 
 * 
 * 
 */

#include "module.h"
#include "mail.h"
#include "modules/memoserv/service.h"

class ModuleMemoChanAccess final
	: public Module
{
	bool notify_access_add = true;
	bool notify_access_del = true;
	bool notify_founder_change = true;
	bool notify_successor_change = true;
	bool email_access_add = false;
	bool email_access_del = false;
	bool email_founder_change = false;
	bool email_successor_change = false;
	bool notice_unregistered_access_add = false;
	bool notice_online_access_add = false;
	bool notice_mask_access_add = false;
	bool notify_self = false;
	Anope::string sender;

	Anope::map<Anope::string> BuildTemplateVars(ChannelInfo *ci, CommandSource &source, NickCore *target,
			const Anope::string &access, const Anope::string &mask) const
	{
		return {
			{ "channel", ci ? ci->name : "" },
			{ "actor", source.GetNick() },
			{ "target", target ? target->display : "" },
			{ "access", access },
			{ "network", Config->GetBlock("networkinfo").Get<const Anope::string>("networkname") },
			{ "account", target ? target->display : "" },
			{ "mask", mask },
			{ "timestamp", Anope::strftime(Anope::CurTime, target) },
		};
	}

	void LoadConfig(Configuration::Block &block)
	{
		notify_access_add = block.Get<bool>("notify_access_add", "yes");
		notify_access_del = block.Get<bool>("notify_access_del", "yes");
		notify_founder_change = block.Get<bool>("notify_founder_change", "yes");
		notify_successor_change = block.Get<bool>("notify_successor_change", "yes");
		email_access_add = block.Get<bool>("email_access_add", "no");
		email_access_del = block.Get<bool>("email_access_del", "no");
		email_founder_change = block.Get<bool>("email_founder_change", "no");
		email_successor_change = block.Get<bool>("email_successor_change", "no");
		notice_unregistered_access_add = block.Get<bool>("notice_unregistered_access_add", "no");
		notice_online_access_add = block.Get<bool>("notice_online_access_add", "no");
		notice_mask_access_add = block.Get<bool>("notice_mask_access_add", "no");
		notify_self = block.Get<bool>("notify_self", "no");
		sender = block.Get<const Anope::string>("sender", "ChanServ");
	}

	Anope::string GetSenderNick(CommandSource &source, ChannelInfo *ci) const
	{
		if (!sender.empty())
			return sender;
		if (ci && ci->WhoSends())
			return ci->WhoSends()->nick;
		if (source.service)
			return source.service->nick;
		if (auto *cs = Config->GetClient("ChanServ"))
			return cs->nick;
		return "ChanServ";
	}

	BotInfo *GetSenderBot(CommandSource &source, ChannelInfo *ci) const
	{
		if (ci && ci->WhoSends())
			return ci->WhoSends();
		if (source.service)
			return source.service;
		return Config->GetClient("ChanServ");
	}

	void TrySendMemo(CommandSource &source, ChannelInfo *ci, NickCore *target, const Anope::string &text)
	{
		if (!target)
			return;
		if (!MemoServ::service)
			return;
		if (!notify_self && source.GetAccount() && source.GetAccount() == target)
			return;

		const auto result = MemoServ::service->Send(GetSenderNick(source, ci), target->display, text, true);
		if (result != MemoServ::MEMO_SUCCESS)
			Log(LOG_DEBUG, "m_memo_chanaccess") << "Unable to send memo to " << target->display << " (result=" << result << ")";
	}

	void TrySendEmail(CommandSource &source, NickCore *target, const Anope::string &subject, const Anope::string &text)
	{
		if (!target)
			return;
		if (Anope::ReadOnly)
			return;
		if (!notify_self && source.GetAccount() && source.GetAccount() == target)
			return;

		const auto &mailconf = Config->GetBlock("mail");
		if (!mailconf.Get<bool>("usemail"))
		{
			Log(LOG_DEBUG, "m_memo_chanaccess") << "Mail disabled (mail:usemail=no); no email sent to " << target->display;
			return;
		}
		if (mailconf.Get<const Anope::string>("sendfrom").empty())
		{
			Log(LOG_DEBUG, "m_memo_chanaccess") << "Mail sendfrom is empty; no email sent to " << target->display;
			return;
		}
		if (target->email.empty())
		{
			Log(LOG_DEBUG, "m_memo_chanaccess") << "Target has no email; no email sent to " << target->display;
			return;
		}

		if (!Mail::Send(target, subject, text))
			Log(LOG_DEBUG, "m_memo_chanaccess") << "Unable to send email to " << target->display;
	}

	void TrySendOnlineNotice(CommandSource &source, ChannelInfo *ci, NickCore *target, const Anope::string &text)
	{
		if (!target)
			return;
		if (!notify_self && source.GetAccount() && source.GetAccount() == target)
			return;

		auto *bi = GetSenderBot(source, ci);
		if (!bi)
			return;

		for (auto *u : target->users)
		{
			if (u)
				u->SendMessage(bi, text);
		}
	}

	void TrySendMaskOnlineNotice(CommandSource &source, ChannelInfo *ci, ChanAccess *access, const Anope::string &text)
	{
		if (!ci || !ci->c || !access)
			return;

		auto *bi = GetSenderBot(source, ci);
		if (!bi)
			return;

		for (const auto &[_, uc] : ci->c->users)
		{
			auto *u = uc->user;
			if (!u)
				continue;
			if (!notify_self && source.GetAccount() && u->Account() && source.GetAccount() == u->Account())
				continue;

			ChannelInfo *next = nullptr;
			if (access->Matches(u, u->Account(), next))
				u->SendMessage(bi, text);
		}
	}

public:
	ModuleMemoChanAccess(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator)
	{
		this->SetAuthor("reverse");
		this->SetVersion("1.0");
		LoadConfig(Config->GetModule(this));
	}

	void OnReload(Configuration::Conf &conf) override
	{
		LoadConfig(conf.GetModule(this));
	}

	void OnAccessAdd(ChannelInfo *ci, CommandSource &source, ChanAccess *access, bool migrated) override
	{
		if (!ci || !access)
			return;
		if (!notify_access_add && !email_access_add && !notice_unregistered_access_add && !notice_online_access_add && !notice_mask_access_add)
			return;

		auto *target = access->GetAccount();
		if (!target)
		{
			Anope::string msg = "Access entry " + access->Mask() + " has been added to the access list for " + ci->name
				+ " by " + source.GetNick() + " (access: " + access->AccessSerialize() + ").";

			if (notice_mask_access_add)
				TrySendMaskOnlineNotice(source, ci, access, msg);
			else if (notice_unregistered_access_add)
				source.Reply("Access entry %s on %s is not a registered account; no memo/email sent.", access->Mask().c_str(), ci->name.c_str());
			return;
		}

		Anope::string msg = "You have been added to the access list for " + ci->name
			+ " by " + source.GetNick() + " (access: " + access->AccessSerialize() + ").";

		if (notify_access_add)
			TrySendMemo(source, ci, target, msg);
		if (notice_online_access_add)
			TrySendOnlineNotice(source, ci, target, msg);
		if (email_access_add)
		{
			auto vars = BuildTemplateVars(ci, source, target, access->AccessSerialize(), access->Mask());
			auto subject = Anope::Template(Language::Translate(target, Config->GetBlock("mail").Get<const Anope::string>(
				"chanaccess_access_subject", "Access update for {channel}").c_str()), vars);
			auto message = Anope::Template(Language::Translate(target, Config->GetBlock("mail").Get<const Anope::string>(
				"chanaccess_access_message", "You have been added to the access list for {channel} by {actor} (access: {access}).").c_str()), vars);
			TrySendEmail(source, target, subject, message);
		}
	}

	void OnAccessDel(ChannelInfo *ci, CommandSource &source, ChanAccess *access, bool migrated) override
	{
		if (!ci || !access)
			return;
		if (!notify_access_del && !email_access_del)
			return;

		auto *target = access->GetAccount();
		if (!target)
			return;

		Anope::string msg = "You have been removed from the access list for " + ci->name
			+ " by " + source.GetNick() + " (access: " + access->AccessSerialize() + ").";

		if (notify_access_del)
			TrySendMemo(source, ci, target, msg);
		if (email_access_del)
		{
			auto vars = BuildTemplateVars(ci, source, target, access->AccessSerialize(), access->Mask());
			auto subject = Anope::Template(Language::Translate(target, Config->GetBlock("mail").Get<const Anope::string>(
				"chanaccess_access_del_subject", "Access removed for {channel}").c_str()), vars);
			auto message = Anope::Template(Language::Translate(target, Config->GetBlock("mail").Get<const Anope::string>(
				"chanaccess_access_del_message", "You have been removed from the access list for {channel} by {actor} (access: {access}).").c_str()), vars);
			TrySendEmail(source, target, subject, message);
		}
	}

	void OnPostCommand(CommandSource &source, Command *command, const std::vector<Anope::string> &params) override
	{
		if (!command)
			return;

		if (command->name.equals_ci("chanserv/set/founder"))
		{
			if (!notify_founder_change && !email_founder_change)
				return;
			if (params.size() < 2)
				return;
			auto *ci = ChannelInfo::Find(params[0]);
			auto *na = NickAlias::Find(params[1]);
			if (!ci || !na || !na->nc)
				return;
			if (ci->GetFounder() != na->nc)
				return;

			Anope::string msg = "You have been set as founder of " + ci->name + " by " + source.GetNick() + ".";
			if (notify_founder_change)
				TrySendMemo(source, ci, na->nc, msg);
			if (email_founder_change)
			{
				auto vars = BuildTemplateVars(ci, source, na->nc, "", "");
				auto subject = Anope::Template(Language::Translate(na->nc, Config->GetBlock("mail").Get<const Anope::string>(
					"chanaccess_founder_subject", "Founder change for {channel}").c_str()), vars);
				auto message = Anope::Template(Language::Translate(na->nc, Config->GetBlock("mail").Get<const Anope::string>(
					"chanaccess_founder_message", "You have been set as founder of {channel} by {actor}.").c_str()), vars);
				TrySendEmail(source, na->nc, subject, message);
			}
			return;
		}

		if (command->name.equals_ci("chanserv/set/successor"))
		{
			if (!notify_successor_change && !email_successor_change)
				return;
			if (params.empty())
				return;
			// Successor can be unset by passing no nick.
			if (params.size() < 2 || params[1].empty())
				return;
			auto *ci = ChannelInfo::Find(params[0]);
			auto *na = NickAlias::Find(params[1]);
			if (!ci || !na || !na->nc)
				return;
			if (ci->GetSuccessor() != na->nc)
				return;

			Anope::string msg = "You have been set as successor of " + ci->name + " by " + source.GetNick() + ".";
			if (notify_successor_change)
				TrySendMemo(source, ci, na->nc, msg);
			if (email_successor_change)
			{
				auto vars = BuildTemplateVars(ci, source, na->nc, "", "");
				auto subject = Anope::Template(Language::Translate(na->nc, Config->GetBlock("mail").Get<const Anope::string>(
					"chanaccess_successor_subject", "Successor change for {channel}").c_str()), vars);
				auto message = Anope::Template(Language::Translate(na->nc, Config->GetBlock("mail").Get<const Anope::string>(
					"chanaccess_successor_message", "You have been set as successor of {channel} by {actor}.").c_str()), vars);
				TrySendEmail(source, na->nc, subject, message);
			}
			return;
		}
	}
};

MODULE_INIT(ModuleMemoChanAccess)
