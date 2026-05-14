/* gs_sexdice: a module that implements the old sexdice tcl script
 * See: https://gist.github.com/Techman-/9b5863414ddb92edfc3a9e21b65377c9
 *
 * Copyright (C) 2019 Michael Hazell <michaelhazell@hotmail.com>
 *
 * You may use this module under the terms of docs/LICENSE, in the Anope source directory
 *
 * Configuration:
 * module { name = "gs_sexdice"; showroller = false; }
 * command { name = "SEXDICE"; service = "GameServ"; command = "gameserv/sexdice"; }
 * fantasy { name = "SEXDICE"; command = "gameserv/sexdice"; prepend_channel = true; }
 */

#include "module.h"

class CommandGSSexDice : public Command
{
	bool showroller;

 public:
	CommandGSSexDice(Module *creator, const Anope::string &sname = "gameserv/sexdice") : Command(creator, sname, 1, 2)
	{
		this->SetDesc(_("Roll the sex dice!"));
		this->SetSyntax(_("\037#channel\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		std::vector<Anope::string> dice1;
		dice1.reserve(10);
		dice1.push_back("kiss");
		dice1.push_back("fondle");
		dice1.push_back("lick");
		dice1.push_back("suck");
		dice1.push_back("touch");
		dice1.push_back("nibble");
		dice1.push_back("do anything you want to");
		dice1.push_back("do anything you want to"); // Greater chance

		std::vector<Anope::string> dice2;
		dice2.reserve(10);
		dice2.push_back("lips");
		dice2.push_back("neck");
		dice2.push_back("chest");
		dice2.push_back("ears");
		dice2.push_back("anywhere you want");
		dice2.push_back("anywhere you want"); // Greater chance
		dice2.push_back("nipple");
		dice2.push_back("toe");
		dice2.push_back("ass");
		dice2.push_back("crotch");

		const Anope::string& chan = params[0];
		ChannelInfo* ci = ChannelInfo::Find(chan);
		BotInfo* gs = Config->GetClient("GameServ");
		if (!ci)
		{
			source.Reply("That channel (\002%s\002) is not registered.", chan.c_str());
			return;
		}

		if (!ci->bi)
		{
			source.Reply("I can't do that in \002%s\002 because no BotServ bot is assigned to it.", ci->name.c_str());
			return;
		}

		if (!ci->c || !ci->c->FindUser(ci->bi))
		{
			source.Reply("I can't speak in \002%s\002 right now (the BotServ bot isn't in the channel).", ci->name.c_str());
			return;
		}

		if (!gs)
		{
			source.Reply("GameServ isn't available right now.");
			return;
		}

		std::vector<User* > users;
		for (const auto& [u, uc] : ci->c->users)
		{
			if(u != ci->bi) // Don't add the BotServ bot
				users.push_back(u);
		}
		if (users.empty())
		{
			IRCD->SendPrivmsg(gs, ci->name, "I couldn't find anyone in the channel to pick from.");
			return;
		}
		int userchoice = rand() % users.size();
		User* u = users[userchoice];

		// http://www.cplusplus.com/forum/beginner/89214/
		int choice1 = rand() % dice1.size();
		int choice2 = rand() % dice2.size();

		showroller = Config->GetModule(this->owner).Get<bool>("showroller", true);
		if (showroller == true)
		{
			IRCD->SendPrivmsg(gs, ci->name, Anope::Format("[SEX DICE] \002%s\002 rolled the Sex Dice!", source.GetUser()->nick.c_str()));
		}
		if (choice2 == 4 || choice2 == 5)
		{
			IRCD->SendPrivmsg(gs, ci->name, Anope::Format("[SEX DICE] \002%s\002, you have to %s \002%s\002 %s!", source.GetUser()->nick.c_str(), dice1[choice1].c_str(), u->nick.c_str(), dice2[choice2].c_str()));
		}
		else
		{
			IRCD->SendPrivmsg(gs, ci->name, Anope::Format("[SEX DICE] \002%s\002, you have to %s \002%s\002 on the %s!", source.GetUser()->nick.c_str(), dice1[choice1].c_str(), u->nick.c_str(), dice2[choice2].c_str()));
		}
	}

	bool OnHelp(CommandSource& source, const Anope::string& subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Rolls the sex dice! Will randomly choose a user in the channel."));
		return true;
	}
};

class GSFantasySexDice : public Module
{
	CommandGSSexDice commandgssexdice;
	bool showroller;

 public:
	GSFantasySexDice(const Anope::string& modname, const Anope::string& creator) : Module(modname, creator, THIRD),
		commandgssexdice(this)
	{
		this->SetAuthor("Techman");
		this->SetVersion("1.0.1");

		if (!ModuleManager::FindModule("gameserv"))
		{
			throw ModuleException("This module requires the GameServ core module to be loaded in order to function.");
		}
	}

	void OnReload(Configuration::Conf& conf) override
	{
		Configuration::Block& block = conf.GetModule(this);
		showroller = block.Get<bool>("showroller", true);
	}
};

MODULE_INIT(GSFantasySexDice)
