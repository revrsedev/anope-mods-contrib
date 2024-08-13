/*
 * (C) 2003-2018 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 *
 * Module ns_login created by k4be and reworked by reverse to make it work on 2.1
 * Include the following in your nickserv.conf
 module { name = "ns_login" }
 command { service = "NickServ"; name = "LOGIN"; command = "nickserv/login"; }
 *
 */

#include "module.h"
#include "modules/ns_cert.h"

static ServiceReference<NickServService> nickserv("NickServService", "NickServ");

typedef std::map<Anope::string, ChannelStatus> NSLoginInfo;

class NSLoginSvsnick
{
public:
	Reference<User> from;
	Anope::string to;
};

class NSLoginRequest final : public IdentifyRequest
{
	CommandSource source;
	Command *cmd;
	Anope::string user;

public:
	NSLoginRequest(Module *o, CommandSource &src, Command *c, const Anope::string &nick, const Anope::string &pass) : IdentifyRequest(o, nick, pass), source(src), cmd(c), user(nick) { }

	void OnSuccess() override
	{
		User *u = User::Find(user, true);
		if (!source.GetUser() || !source.service)
			return;

		NickAlias *na = NickAlias::Find(user);
		if (!na)
			return;

		Log(LOG_COMMAND, source, cmd) << "for " << na->nick;

		/* Nick is being held by us, release it */
		if (na->HasExt("HELD"))
		{
			nickserv->Release(na);
			source.Reply(_("Service's hold on \002%s\002 has been released."), na->nick.c_str());
		}
		if (!u)
		{
			if (IRCD->CanSVSNick)
				IRCD->SendForceNickChange(source.GetUser(), GetAccount(), Anope::CurTime);
			source.GetUser()->Login(na->nc); // Identify the user using the command if they arent identified
			Log(LOG_COMMAND, source, cmd) << "and identified to " << na->nick << " (" << na->nc->display << ")";
			source.Reply(_("Password accepted - you are now recognized."));
		}
		// If the user being recovered is identified for the account of the nick then the user is the
		// same person that is executing the command, so kill them off (old GHOST command).
		else if (u->Account() == na->nc)
		{
			if (!source.GetAccount() && na->nc->HasExt("NS_SECURE"))
			{
				source.GetUser()->Login(u->Account());
				Log(LOG_COMMAND, source, cmd) << "and was automatically identified to " << u->Account()->display;
			}

			if (Config->GetModule("ns_login")->Get<bool>("restoreonrecover"))
			{
				if (!u->chans.empty())
				{
					NSLoginInfo *ei = source.GetUser()->Extend<NSLoginInfo>("login");
					for (User::ChanUserList::iterator it = u->chans.begin(), it_end = u->chans.end(); it != it_end; ++it)
						(*ei)[it->first->name] = it->second->status;
				}
			}

			u->SendMessage(source.service, _("This nickname has been recovered by %s. If you did not do\n"
							"this then %s may have your password, and you should change it."),
							source.GetNick().c_str(), source.GetNick().c_str());

			Anope::string buf = source.command.upper() + " command used by " + source.GetNick();
			u->Kill(*source.service, buf);

			source.Reply(_("Ghost with your nick has been killed."));

			if (IRCD->CanSVSNick)
				IRCD->SendForceNickChange(source.GetUser(), GetAccount(), Anope::CurTime);
		}
		/* User is not identified or not identified to the same account as the person using this command */
		else
		{
			if (!source.GetAccount() && na->nc->HasExt("NS_SECURE"))
			{
				source.GetUser()->Login(na->nc); // Identify the user using the command if they arent identified
				Log(LOG_COMMAND, source, cmd) << "and was automatically identified to " << na->nick << " (" << na->nc->display << ")";
				source.Reply(_("You have been logged in as \002%s\002."), na->nc->display.c_str());
			}

			u->SendMessage(source.service, _("This nickname has been recovered by %s."), source.GetNick().c_str());

			if (IRCD->CanSVSNick)
			{
				NSLoginSvsnick *svs = u->Extend<NSLoginSvsnick>("login_svsnick");
				svs->from = source.GetUser();
				svs->to = u->nick;
			}

			if (nickserv)
				nickserv->Collide(u, na);

			if (IRCD->CanSVSNick)
			{
				/* If we can svsnick then release our hold and svsnick the user using the command */
				if (nickserv)
					nickserv->Release(na);

				source.Reply(_("You have regained control of \002%s\002."), u->nick.c_str());
			}
			else
			{
				source.Reply(_("The user with your nick has been removed. Use this command again\n"
						"to release services's hold on your nick."));
			}
		}
	}

	void OnFail() override
	{
		if (NickAlias::Find(GetAccount()) != NULL)
		{
			source.Reply(ACCESS_DENIED);
			if (!GetPassword().empty())
			{
				Log(LOG_COMMAND, source, cmd) << "with an invalid password for " << GetAccount();
				if (source.GetUser())
					source.GetUser()->BadPassword();
			}
		}
		else
			source.Reply(NICK_X_NOT_REGISTERED, GetAccount().c_str());
	}
};

class CommandNSLogin final : public Command
{
public:
	CommandNSLogin(Module *creator) : Command(creator, "nickserv/login", 1, 2)
	{
		this->SetDesc(_("Identifies you to services and regains control of your nick"));
		this->SetSyntax(_("\037nickname\037 [\037password\037]"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		const Anope::string &nick = params[0];
		const Anope::string &pass = params.size() > 1 ? params[1] : "";

		User *user = User::Find(nick, true);

		if (user && source.GetUser() == user)
		{
			source.Reply(_("You can't %s yourself!"), source.command.lower().c_str());
			return;
		}

		const NickAlias *na = NickAlias::Find(nick);

		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, nick.c_str());
			return;
		}
		else if (na->nc->HasExt("NS_SUSPENDED"))
		{
			source.Reply(NICK_X_SUSPENDED, na->nick.c_str());
			return;
		}

		bool ok = false;
		if (source.GetAccount() == na->nc)
			ok = true;

		NSCertList *cl = na->nc->GetExt<NSCertList>("certificates");
		if (source.GetUser() && !source.GetUser()->fingerprint.empty() && cl && cl->FindCert(source.GetUser()->fingerprint))
			ok = true;

		if (ok == false && !pass.empty())
		{
			NSLoginRequest *req = new NSLoginRequest(owner, source, this, na->nick, pass);
			FOREACH_MOD(OnCheckAuthentication, (source.GetUser(), req));
			req->Dispatch();
		}
		else
		{
			NSLoginRequest req(owner, source, this, na->nick, pass);

			if (ok)
				req.OnSuccess();
			else
				req.OnFail();
		}
	}

	bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Recovers your nick from another user or from services.\n"
				"If services are currently holding your nick, the hold\n"
				"will be released. If another user is holding your nick\n"
				"and is identified they will be killed (similar to the old\n"
				"GHOST command). If they are not identified they will be\n"
				"forced off of the nick."));
		source.Reply(_("Tells %s that you are really the owner of this\n"
				"nick.  Many commands require you to authenticate yourself\n"
				"with this command before you use them.  The password\n"
				"should be the same one you sent with the \002REGISTER\002\n"
				"command."), source.service->nick.c_str());
		return true;
	}
};

class NSLogin final : public Module
{
	CommandNSLogin commandnslogin;
	PrimitiveExtensibleItem<NSLoginInfo> login;
	PrimitiveExtensibleItem<NSLoginSvsnick> login_svsnick;

public:
	NSLogin(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR),
		commandnslogin(this), login(this, "login"), login_svsnick(this, "login_svsnick")
	{

		if (Config->GetModule("nickserv")->Get<bool>("nonicknameownership"))
			throw ModuleException(modname + " can not be used with options:nonicknameownership enabled");

	}

	void OnUserNickChange(User *u, const Anope::string &oldnick) override
	{
		if (Config->GetModule(this)->Get<bool>("restoreonrecover"))
		{
			NSLoginInfo *ei = login.Get(u);
			BotInfo *NickServ = Config->GetClient("NickServ");

			if (ei != NULL && NickServ != NULL)
				for (NSLoginInfo::iterator it = ei->begin(), it_end = ei->end(); it != it_end;)
				{
					Channel *c = Channel::Find(it->first);
					const Anope::string &cname = it->first;
					++it;

					/* User might already be on the channel */
					if (u->FindChannel(c))
						this->OnJoinChannel(u, c);
					else if (IRCD->CanSVSJoin)
						IRCD->SendSVSJoin(NickServ, u, cname, "");
				}
		}

		NSLoginSvsnick *svs = login_svsnick.Get(u);
		if (svs)
		{
			if (svs->from)
			{
				// svsnick from to to
				IRCD->SendForceNickChange(svs->from, svs->to, Anope::CurTime);
			}

			login_svsnick.Unset(u);
		}
	}

	void OnJoinChannel(User *u, Channel *c) override
	{
		if (Config->GetModule(this)->Get<bool>("restoreonrecover"))
		{
			NSLoginInfo *ei = login.Get(u);

			if (ei != NULL)
			{
				NSLoginInfo::iterator it = ei->find(c->name);
				if (it != ei->end())
				{
					for (size_t i = 0; i < it->second.Modes().length(); ++i)
						c->SetMode(c->ci->WhoSends(), ModeManager::FindChannelModeByChar(it->second.Modes()[i]), u->GetUID());

					ei->erase(it);
					if (ei->empty())
						login.Unset(u);
				}
			}
		}
	}
};

MODULE_INIT(NSLogin)
