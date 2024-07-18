/*
m_sqlauth.cpp
2024 Jean "reverse" Chevronnet
Module for Anope IRC Services v2.1, lets users authenticate with
credentials stored in a pre-existing SQL server instead of the internal
Anope database.

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

#include "module.h"
#include "modules/sql.h"
#include "modules/encryption.h" // Include Anope's encryption header
#include "bcrypt/crypt_blowfish.c" // Include the bcrypt implementation

static Module *me;

class SQLAuthResult final : public SQL::Interface
{
    Reference<User> user;
    IdentifyRequest *req;
    Anope::string currPass;

public:
    SQLAuthResult(User *u, const Anope::string &cp, IdentifyRequest *r) : SQL::Interface(me), user(u), req(r)
    {
        req->Hold(me);
        this->currPass = cp;
    }

    ~SQLAuthResult()
    {
        req->Release(me);
    }

    void OnResult(const SQL::Result &r) override
    {
        if (r.Rows() == 0)
        {
            Log(LOG_COMMAND) << "[sql_auth]: User @" << req->GetAccount() << "@ NOT found";
            delete this;
            return;
        }

        Log(LOG_COMMAND) << "[sql_auth]: User @" << req->GetAccount() << "@ found";
        Log(LOG_COMMAND) << "[sql_auth]: Authentication for user @" << req->GetAccount() << "@ processing...";

        Anope::string hash;
        Anope::string email;

        try
        {
            hash = r.Get(0, "password");
            email = r.Get(0, "email");
        }
        catch (const SQL::Exception &) { }

        // Normalize bcrypt hash prefix
        if (hash.find("bcrypt$$") == 0)
        {
            hash = "$" + hash.substr(8);
        }

        //Log(LOG_COMMAND) << "[sql_auth]: Normalized hash: " << hash;

        // Use bcrypt functions directly
        char hash_output[64];
        if (!_crypt_blowfish_rn(currPass.c_str(), hash.c_str(), hash_output, sizeof(hash_output)))
        {
            Log(LOG_COMMAND) << "[sql_auth]: Bcrypt comparison failed";
            delete this;
            return;
        }

        bool is_match = (hash == hash_output);
        //Log(LOG_COMMAND) << "[sql_auth]: Password comparison result: " << is_match;

        if (!is_match)
        {
            Log(LOG_COMMAND) << "[sql_auth]: ERROR: hash NOT EQUAL pass";
            //Log(LOG_COMMAND) << "[sql_auth]: Provided password: " << currPass;
            //Log(LOG_COMMAND) << "[sql_auth]: Retrieved hash: " << hash;
            //Log(LOG_COMMAND) << "[sql_auth]: Manually hashed provided password: " << hash_output;

            Log(LOG_COMMAND) << "[sql_auth]: Unsuccessful authentication for " << req->GetAccount();
            delete this;
            return;
        }

        Log(LOG_COMMAND) << "[sql_auth]: User @" << req->GetAccount() << "@ LOGGED IN";

        NickAlias *na = NickAlias::Find(req->GetAccount());
        BotInfo *NickServ = Config->GetClient("NickServ");
        if (na == NULL)
        {
            na = new NickAlias(req->GetAccount(), new NickCore(req->GetAccount()));
            FOREACH_MOD(OnNickRegister, (user, na, ""));
            if (user && NickServ)
                user->SendMessage(NickServ, _("Your account \002%s\002 has been confirmed."), na->nick.c_str());
        }

        if (!email.empty() && email != na->nc->email)
        {
            na->nc->email = email;
            if (user && NickServ)
                user->SendMessage(NickServ, _("E-mail set to \002%s\002."), email.c_str());
        }

        req->Success(me);
        delete this;
    }

    void OnError(const SQL::Result &r) override
    {
        Log(this->owner) << "[sql_auth]: Error when executing query " << r.GetQuery().query << ": " << r.GetError();
        delete this;
    }
};

class ModuleSQLAuth final : public Module
{
    Anope::string engine;
    Anope::string query;
    Anope::string disable_reason, disable_email_reason;

    ServiceReference<SQL::Provider> SQL;

public:
    ModuleSQLAuth(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, EXTRA | VENDOR)
    {
        me = this;
    }

    void OnReload(Configuration::Conf *conf) override
    {
        Configuration::Block *config = conf->GetModule(this);
        this->engine = config->Get<const Anope::string>("engine");
        this->query = config->Get<const Anope::string>("query");
        this->disable_reason = config->Get<const Anope::string>("disable_reason");
        this->disable_email_reason = config->Get<Anope::string>("disable_email_reason");

        this->SQL = ServiceReference<SQL::Provider>("SQL::Provider", this->engine);
    }

    EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
    {
        if (!this->disable_reason.empty() && (command->name == "nickserv/register" || command->name == "nickserv/group"))
        {
            source.Reply(this->disable_reason);
            return EVENT_STOP;
        }

        if (!this->disable_email_reason.empty() && command->name == "nickserv/set/email")
        {
            source.Reply(this->disable_email_reason);
            return EVENT_STOP;
        }

        return EVENT_CONTINUE;
    }

    void OnCheckAuthentication(User *u, IdentifyRequest *req) override
    {
        if (!this->SQL)
        {
            Log(this) << "[sql_auth]: Unable to find SQL engine";
            return;
        }

        SQL::Query q(this->query);
        q.SetValue("a", req->GetAccount());
        q.SetValue("p", req->GetPassword());
        if (u)
        {
            q.SetValue("n", u->nick);
            q.SetValue("i", u->ip.addr());
        }
        else
        {
            q.SetValue("n", "");
            q.SetValue("i", "");
        }

        this->SQL->Run(new SQLAuthResult(u, req->GetPassword(), req), q);
        Log(LOG_COMMAND) << "[sql_auth]: Checking authentication for " << req->GetAccount();
    }

    void OnPreNickExpire(NickAlias *na, bool &expire) override
    {
        // We can't let nicks expire if they still have a group or
        // there will be a zombie account left over that can't be
        // authenticated to.
        if (na->nick == na->nc->display && na->nc->aliases->size() > 1)
            expire = false;
    }
};

MODULE_INIT(ModuleSQLAuth)
