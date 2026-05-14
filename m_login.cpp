/*
 * (C) 2025 reverse Juean Chevronnet
 * Contact me at reverse@tchatzone.fr
 * IRC: irc.tchatzone.fr Port:+6697 (tls)
 * Salon: #devel
 *
 * Module ns_login created by k4be and reworked by reverse to make it work on 2.1
 * Include the following in your nickserv.conf
 *
 * module { name = "m_login" }
 * command { service = "NickServ"; name = "LOGIN"; command = "nickserv/login"; }
 *
 */

#include "module.h"
#include "modules/nickserv/cert.h"
#include "modules/nickserv/service.h"
 
typedef std::map<Anope::string, ChannelStatus> NSLoginInfo;
 
class NSLoginSvsnick final
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
     NSLoginRequest(Module *o, CommandSource &src, Command *c, const Anope::string &nick, const Anope::string &pass)
         : IdentifyRequest(o, nick, pass, src.ip)
         , source(src)
         , cmd(c)
         , user(nick)
     {
     }
 
     void OnSuccess(NickAlias *na) override
     {
        User *u = User::Find(user, true);
         if (!source.GetUser() || !source.service)
             return;
 
         Log(LOG_COMMAND, source, cmd) << "for " << na->nick;
 
        /* Nick is being held by us, release it */
         if (na->HasExt("HELD"))
         {
             if (NickServ::service)
                 NickServ::service->Release(na);
             source.Reply(_("Services' hold on \002%s\002 has been released."), na->nick.c_str());
         }

        // After successful authentication always identify the user to the target account.
        source.GetUser()->Identify(na);

        // If the requested nick is already being used by the requesting user,
        // just identify them. Do not treat this as a recover/ghost.
        if (u && u == source.GetUser())
        {
            Log(LOG_COMMAND, source, cmd) << "and identified to " << na->nick << " (" << na->nc->display << ")";
            source.Reply(_("Password accepted - you are now recognized."));
            return;
        }

        if (!u)
        {
            if (IRCD->CanSVSNick)
                IRCD->SendForceNickChange(source.GetUser(), na->nick, Anope::CurTime);
            Log(LOG_COMMAND, source, cmd) << "and identified to " << na->nick << " (" << na->nc->display << ")";
            source.Reply(_("Password accepted - you are now recognized."));
        }
        else if (u->Account() == na->nc)
         {
             if (Config->GetModule("m_login").Get<bool>("restoreonrecover"))
             {
                 if (!u->chans.empty())
                 {
                     NSLoginInfo *ei = source.GetUser()->Extend<NSLoginInfo>("login");
                     for (auto &it : u->chans)
                         (*ei)[it.first->name] = it.second->status;
                 }
             }
 
             u->SendMessage(source.service, _("This nickname has been recovered by %s. If you did not do\n"
                                              "this then %s may have your password, and you should change it."),
                            source.GetNick().c_str(), source.GetNick().c_str());
 
             Anope::string buf = source.command.upper() + " command used by " + source.GetNick();
             u->Kill(*source.service, buf);
 
             source.Reply(_("Ghost with your nick has been killed."));
 
             if (IRCD->CanSVSNick)
                IRCD->SendForceNickChange(source.GetUser(), na->nick, Anope::CurTime);
         }
         else
         {
             u->SendMessage(source.service, _("This nickname has been recovered by %s."), source.GetNick().c_str());
 
             if (IRCD->CanSVSNick)
             {
                 NSLoginSvsnick *svs = u->Extend<NSLoginSvsnick>("login_svsnick");
                 svs->from = source.GetUser();
                 svs->to = u->nick;
             }
 
             if (NickServ::service)
                 NickServ::service->Collide(u, na);
 
             if (IRCD->CanSVSNick)
             {
                 if (NickServ::service)
                     NickServ::service->Release(na);
 
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
        this->RequireUser(true);
     }
 
     void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
     {
         const Anope::string &nick = params[0];
         const Anope::string &pass = params.size() > 1 ? params[1] : "";
 
         NickAlias *na = NickAlias::Find(nick);
 
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
 
         bool ok = (source.GetAccount() == na->nc);
 
         auto *cl = na->nc->GetExt<NickServ::CertList>(NICKSERV_CERT_EXT);
         if (source.GetUser() && !source.GetUser()->fingerprint.empty() && cl && cl->FindCert(source.GetUser()->fingerprint))
             ok = true;
 
         if (!ok && !pass.empty())
         {
             NSLoginRequest *req = new NSLoginRequest(owner, source, this, na->nick, pass);
             FOREACH_MOD(OnCheckAuthentication, (source.GetUser(), req));
             req->Dispatch();
         }
         else
         {
             NSLoginRequest req(owner, source, this, na->nick, pass);
             if (ok)
                 req.OnSuccess(na);
             else
                 req.OnFail();
         }
     }
 };
 
 class NSLogin final : public Module
 {
     CommandNSLogin commandnslogin;
    PrimitiveExtensibleItem<NSLoginInfo> login;
    PrimitiveExtensibleItem<NSLoginSvsnick> login_svsnick;
 
 public:
     NSLogin(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, VENDOR),
        commandnslogin(this)
        , login(this, "login")
        , login_svsnick(this, "login_svsnick")
     {
         if (Config->GetModule("nickserv").Get<bool>("nonicknameownership"))
             throw ModuleException(modname + " cannot be used with options:nonicknameownership enabled");
     }

    void OnUserNickChange(User *u, const Anope::string &oldnick) override
    {
        if (Config->GetModule(this).Get<bool>("restoreonrecover"))
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
                IRCD->SendForceNickChange(svs->from, svs->to, Anope::CurTime);
            login_svsnick.Unset(u);
        }
    }

    void OnJoinChannel(User *u, Channel *c) override
    {
        if (Config->GetModule(this).Get<bool>("restoreonrecover"))
        {
            NSLoginInfo *ei = login.Get(u);

            if (ei != NULL)
            {
                NSLoginInfo::iterator it = ei->find(c->name);
                if (it != ei->end())
                {
                    for (auto mode : it->second.Modes())
                        c->SetMode(c->WhoSends(), mode, u->GetUID());

                    ei->erase(it);
                    if (ei->empty())
                        login.Unset(u);
                }
            }
        }
    }
 };
 
 MODULE_INIT(NSLogin)
 
