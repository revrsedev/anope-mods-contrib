/*
 * m_nickserv_oauth.cpp
 * 2026 Jean "reverse" Chevronnet
 * 
 * Module for Anope IRC Services v2.1
 * Adds IDENTIFYOAUTH command to NickServ for JWT-based authentication
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License.
 */

/// BEGIN CMAKE
/// find_package(OpenSSL REQUIRED)
/// target_link_libraries(${SO} PUBLIC OpenSSL::Crypto OpenSSL::SSL)
/// END CMAKE

#include "module.h"
#include <jwt-cpp/jwt.h>
#include <openssl/evp.h>

static Module *me;

class CommandNSIdentifyOAuth final : public Command
{
public:
    Anope::string jwt_secret;
    Anope::string jwt_issuer;

    CommandNSIdentifyOAuth(Module *creator)
        : Command(creator, "nickserv/identifyoauth", 2, 2)
    {
        this->SetDesc(_("Identify to services using an OAuth/JWT token"));
        this->SetSyntax(_("\037nickname\037 \037token\037"));
        this->AllowUnregistered(true);
    }

    void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
    {
        const Anope::string &username = params[0];
        const Anope::string &token = params[1];

        User *u = source.GetUser();
        BotInfo *bi = Config->GetClient("NickServ");

        if (!u || !bi)
            return;

        Log(LOG_COMMAND, source, this) << "to authenticate as " << username << " using OAuth token";

        // Find the account
        NickAlias *na = NickAlias::Find(username);
        if (!na)
        {
            source.Reply(_("Account \002%s\002 is not registered."), username.c_str());
            Log(me, "oauth") << u->GetMask() << " tried to IDENTIFYOAUTH as \002" << username << "\002 but account does not exist";
            u->BadPassword();
            return;
        }

        NickCore *nc = na->nc;
        if (!nc)
        {
            source.Reply(_("Account \002%s\002 is not registered."), username.c_str());
            u->BadPassword();
            return;
        }

        // Check if account is suspended
        if (nc->HasExt("NS_SUSPENDED"))
        {
            source.Reply(_("Your account has been suspended."));
            Log(me, "oauth") << u->GetMask() << " tried to IDENTIFYOAUTH as suspended account \002" << username << "\002";
            u->BadPassword();
            return;
        }

        // Validate JWT token
        try
        {
            std::string token_str(token.c_str());
            auto decoded = jwt::decode(token_str);

            // Debug logging
            Log(me, "oauth") << "Token decoded - Algorithm: " << decoded.get_algorithm();
            if (decoded.has_issuer())
                Log(me, "oauth") << "Token issuer: " << decoded.get_issuer();
            if (decoded.has_payload_claim("sub"))
                Log(me, "oauth") << "Token sub: " << decoded.get_payload_claim("sub").as_string();
            
            // Verify token signature and issuer if configured
            if (!this->jwt_secret.empty())
            {
                std::string secret_str(this->jwt_secret.c_str());
                std::string expected_issuer(this->jwt_issuer.c_str());

                Log(me, "oauth") << "Verifying with secret length: " << secret_str.length() 
                                 << " expected issuer: " << expected_issuer;

                auto verifier = jwt::verify()
                    .allow_algorithm(jwt::algorithm::hs256{secret_str});

                // Only verify issuer if the token has one AND we have an expected issuer
                if (!expected_issuer.empty() && decoded.has_issuer())
                    verifier.with_issuer(expected_issuer);

                verifier.verify(decoded);
            }

            // Extract username from token - check multiple possible claims
            std::string token_username;
            if (decoded.has_payload_claim("sub"))
                token_username = decoded.get_payload_claim("sub").as_string();
            else if (decoded.has_payload_claim("name"))
                token_username = decoded.get_payload_claim("name").as_string();
            else if (decoded.has_payload_claim("username"))
                token_username = decoded.get_payload_claim("username").as_string();
            
            // If no username in token, we need to look up by user_id
            if (token_username.empty() && decoded.has_payload_claim("user_id"))
            {
                Log(me, "oauth") << "Token contains user_id but no username claim - cannot verify identity match";
            }

            // Verify token username matches requested username
            if (!token_username.empty())
            {
                Anope::string token_user_anope(token_username.c_str());
                if (!token_user_anope.equals_ci(username))
                {
                    source.Reply(_("Token username does not match requested account."));
                    Log(me, "oauth") << u->GetMask() << " tried to IDENTIFYOAUTH as \002" << username 
                                     << "\002 but token is for \002" << token_username << "\002";
                    u->BadPassword();
                    return;
                }
            }

            // Check token expiration
            if (decoded.has_expires_at())
            {
                auto exp_time = decoded.get_expires_at();
                auto now = std::chrono::system_clock::now();
                if (exp_time < now)
                {
                    source.Reply(_("OAuth token has expired."));
                    Log(me, "oauth") << u->GetMask() << " tried to IDENTIFYOAUTH with expired token for \002" << username << "\002";
                    u->BadPassword();
                    return;
                }
            }

            // Token is valid - identify the user
            u->Identify(na);
            
            source.Reply(_("Password accepted - you are now recognized."));
            Log(me, "oauth") << u->GetMask() << " successfully identified to account \002" << nc->display << "\002 using OAuth";
            
            // If the user's current nickname matches the account, update display
            if (u->nick.equals_ci(nc->display))
            {
                Configuration::Block modconf = Config->GetModule("ns_identify");
                if (modconf.Get<bool>("modeonid", "yes"))
                {
                    // Set correct modes in channels
                    for (const auto &[_, cc] : u->chans)
                    {
                        Channel *c = cc->chan;
                        if (c)
                            c->SetCorrectModes(u, true);
                    }
                }
                
                // Apply configured user modes on identify
                const Anope::string &modesonid = modconf.Get<const Anope::string>("modesonid");
                if (!modesonid.empty())
                    u->SetModes(bi, modesonid);
            }

            FOREACH_MOD(OnNickIdentify, (u));
        }
        catch (const jwt::error::token_verification_exception &e)
        {
            source.Reply(_("Invalid or malformed OAuth token."));
            Log(me, "oauth") << u->GetMask() << " failed JWT verification for \002" << username 
                             << "\002: " << e.what();
            u->BadPassword();
        }
        catch (const std::exception &e)
        {
            source.Reply(_("OAuth authentication failed: Invalid token."));
            Log(me, "oauth") << u->GetMask() << " IDENTIFYOAUTH error for \002" << username 
                             << "\002: " << e.what();
            u->BadPassword();
        }
    }

    bool OnHelp(CommandSource &source, const Anope::string &subcommand) override
    {
        source.Reply(" ");
        source.Reply(_("Authenticate to services using a JWT OAuth token obtained from\n"
                       "the web interface. This command is typically used automatically\n"
                       "by web chat clients and should not be used manually."));
        source.Reply(" ");
        source.Reply(_("Syntax: \002IDENTIFYOAUTH \037nickname\037 \037token\037\002"));
        source.Reply(" ");
        source.Reply(_("Example:"));
        source.Reply(_("  /msg NickServ IDENTIFYOAUTH YourNick eyJhbGc..."));
        return true;
    }

    void OnServHelp(CommandSource &source, HelpWrapper &help) override
    {
        source.Reply(_("    IDENTIFYOAUTH  Identify using an OAuth token"));
    }

    void OnSyntaxError(CommandSource &source, const Anope::string &subcommand) override
    {
        source.Reply(_("Syntax: \002IDENTIFYOAUTH \037nickname\037 \037token\037\002"));
        source.Reply(_("Type \002/msg %s HELP IDENTIFYOAUTH\002 for more information."), source.service->nick.c_str());
    }
};

class ModuleNSIdentifyOAuth final : public Module
{
private:
    CommandNSIdentifyOAuth commandnsidentifyoauth;

public:
    ModuleNSIdentifyOAuth(const Anope::string &modname, const Anope::string &creator)
        : Module(modname, creator, EXTRA | VENDOR)
        , commandnsidentifyoauth(this)
    {
        me = this;
    }

    void OnReload(Configuration::Conf &conf) override
    {
        Configuration::Block &config = conf.GetModule(this);
        
        // Read JWT configuration from module config
        Anope::string jwt_secret = config.Get<const Anope::string>("jwt_secret", "");
        Anope::string jwt_issuer = config.Get<const Anope::string>("jwt_issuer", "");
        
        // Update command with new config
        commandnsidentifyoauth.jwt_secret = jwt_secret;
        commandnsidentifyoauth.jwt_issuer = jwt_issuer;
        
        if (jwt_secret.empty())
        {
            Log(this) << "Warning: jwt_secret not configured - JWT signature verification disabled";
        }
        
        Log(this) << "IDENTIFYOAUTH command loaded (JWT verification: " 
                  << (jwt_secret.empty() ? "disabled" : "enabled") << ")";
    }
};

MODULE_INIT(ModuleNSIdentifyOAuth)
