#include "helpserv.h"
#include "timers.h"

#include <algorithm>
#include <cstdarg>
#include <utility>

using helpserv_ticket_map = Anope::unordered_map<HelpServTicket *>;
static Serialize::Checker<helpserv_ticket_map> HelpServTicketList(HELPSERV_TICKET_DATA_TYPE);

using helpserv_state_map = Anope::unordered_map<HelpServState *>;
static Serialize::Checker<helpserv_state_map> HelpServStateList(HELPSERV_STATE_DATA_TYPE);

static Anope::string TicketKey(uint64_t id)
{
	return Anope::ToString(id);
}

static int TicketClampPriority(int p)
{
	if (p < 0)
		return 0;
	if (p > 2)
		return 2;
	return p;
}

static Anope::string TicketNormalizeState(const Anope::string& state)
{
	if (state.equals_ci("waiting") || state.equals_ci("wait"))
		return "waiting";
	return "open";
}

HelpServTicket::HelpServTicket(uint64_t ticket_id)
	: Serializable(HELPSERV_TICKET_DATA_TYPE)
{
	if (!ticket_id)
		throw ModuleException("HelpServ: ticket id must be non-zero");
	this->id = ticket_id;
	this->key = TicketKey(ticket_id);
	HelpServTicketList->insert_or_assign(this->key, this);
}

HelpServTicket::~HelpServTicket()
{
	HelpServTicketList->erase(this->key);
}

HelpServState::HelpServState()
	: Serializable(HELPSERV_STATE_DATA_TYPE)
{
	HelpServStateList->insert_or_assign(this->name, this);
}

HelpServState::~HelpServState()
{
	HelpServStateList->erase(this->name);
}

HelpServTicketDataType::HelpServTicketDataType(Module* owner)
	: Serialize::Type(HELPSERV_TICKET_DATA_TYPE, owner)
{
}

void HelpServTicketDataType::Serialize(Serializable* obj, Serialize::Data& data) const
{
	const auto* t = static_cast<const HelpServTicket*>(obj);

	data.Store("id", static_cast<uint64_t>(t->id));
	data.Store("account", t->account);
	data.Store("nick", t->nick);
	data.Store("requester", t->requester);
	data.Store("topic", t->topic);
	data.Store("message", t->message);
	data.Store("priority", static_cast<int64_t>(TicketClampPriority(t->priority)));
	data.Store("state", TicketNormalizeState(t->state));
	data.Store("wait_reason", t->wait_reason);
	data.Store("assigned", t->assigned);
	data.Store("created", static_cast<int64_t>(t->created));
	data.Store("updated", static_cast<int64_t>(t->updated));

	data.Store("notecount", static_cast<uint64_t>(t->notes.size()));
	for (uint64_t i = 0; i < static_cast<uint64_t>(t->notes.size()); ++i)
	{
		const Anope::string prefix = "note" + Anope::ToString(i) + ".";
		data.Store(prefix + "text", t->notes[static_cast<size_t>(i)]);
	}
}

Serializable* HelpServTicketDataType::Unserialize(Serializable* obj, Serialize::Data& data) const
{
	uint64_t id = 0;
	data.TryLoad("id", id);
	if (!id)
		return nullptr;

	HelpServTicket* t = nullptr;
	if (obj)
	{
		t = anope_dynamic_static_cast<HelpServTicket*>(obj);
	}
	else
	{
		const Anope::string key = TicketKey(id);
		auto it = HelpServTicketList->find(key);
		if (it != HelpServTicketList->end())
			t = it->second;
		if (!t)
			t = new HelpServTicket(id);
	}

	t->id = id;
	t->key = TicketKey(id);
	data.TryLoad("account", t->account);
	data.TryLoad("nick", t->nick);
	data.TryLoad("requester", t->requester);
	data.TryLoad("topic", t->topic);
	data.TryLoad("message", t->message);
	data.TryLoad("priority", t->priority);
	t->priority = TicketClampPriority(t->priority);
	data.TryLoad("state", t->state);
	t->state = TicketNormalizeState(t->state);
	data.TryLoad("wait_reason", t->wait_reason);
	data.TryLoad("assigned", t->assigned);
	data.TryLoad("created", t->created);
	data.TryLoad("updated", t->updated);

	uint64_t notecount = 0;
	data.TryLoad("notecount", notecount);
	t->notes.clear();
	t->notes.resize(static_cast<size_t>(notecount));
	for (uint64_t i = 0; i < notecount; ++i)
	{
		const Anope::string prefix = "note" + Anope::ToString(i) + ".";
		data.TryLoad(prefix + "text", t->notes[static_cast<size_t>(i)]);
	}

	return t;
}

HelpServStateDataType::HelpServStateDataType(Module* owner)
	: Serialize::Type(HELPSERV_STATE_DATA_TYPE, owner)
{
}

void HelpServStateDataType::Serialize(Serializable* obj, Serialize::Data& data) const
{
	const auto* st = static_cast<const HelpServState*>(obj);
	data.Store("name", st->name);
	data.Store("next_ticket_id", static_cast<uint64_t>(st->next_ticket_id));

	data.Store("help_requests", static_cast<uint64_t>(st->help_requests));
	data.Store("search_requests", static_cast<uint64_t>(st->search_requests));
	data.Store("search_hits", static_cast<uint64_t>(st->search_hits));
	data.Store("search_misses", static_cast<uint64_t>(st->search_misses));
	data.Store("unknown_topics", static_cast<uint64_t>(st->unknown_topics));
	data.Store("helpme_requests", static_cast<uint64_t>(st->helpme_requests));
	data.Store("request_requests", static_cast<uint64_t>(st->request_requests));
	data.Store("cancel_requests", static_cast<uint64_t>(st->cancel_requests));
	data.Store("list_requests", static_cast<uint64_t>(st->list_requests));
	data.Store("next_requests", static_cast<uint64_t>(st->next_requests));
	data.Store("view_requests", static_cast<uint64_t>(st->view_requests));
	data.Store("take_requests", static_cast<uint64_t>(st->take_requests));
	data.Store("assign_requests", static_cast<uint64_t>(st->assign_requests));
	data.Store("note_requests", static_cast<uint64_t>(st->note_requests));
	data.Store("close_requests", static_cast<uint64_t>(st->close_requests));
	data.Store("priority_requests", static_cast<uint64_t>(st->priority_requests));
	data.Store("wait_requests", static_cast<uint64_t>(st->wait_requests));
	data.Store("unwait_requests", static_cast<uint64_t>(st->unwait_requests));
	data.Store("notify_requests", static_cast<uint64_t>(st->notify_requests));

	data.Store("topiccount", static_cast<uint64_t>(st->topic_requests.size()));
	uint64_t i = 0;
	for (const auto& [topic, count] : st->topic_requests)
	{
		const Anope::string prefix = "topic" + Anope::ToString(i) + ".";
		data.Store(prefix + "name", topic);
		data.Store(prefix + "count", static_cast<uint64_t>(count));
		++i;
	}

	data.Store("helpme_cooldown_count", static_cast<uint64_t>(st->last_helpme_by_key.size()));
	i = 0;
	for (const auto& it : st->last_helpme_by_key)
	{
		const Anope::string prefix = "helpme_cooldown" + Anope::ToString(i) + ".";
		data.Store(prefix + "key", it.first);
		data.Store(prefix + "ts", static_cast<int64_t>(it.second));
		++i;
	}

	data.Store("request_cooldown_count", static_cast<uint64_t>(st->last_request_by_key.size()));
	i = 0;
	for (const auto& it : st->last_request_by_key)
	{
		const Anope::string prefix = "request_cooldown" + Anope::ToString(i) + ".";
		data.Store(prefix + "key", it.first);
		data.Store(prefix + "ts", static_cast<int64_t>(it.second));
		++i;
	}
}

Serializable* HelpServStateDataType::Unserialize(Serializable* obj, Serialize::Data& data) const
{
	Anope::string name;
	data.TryLoad("name", name);
	if (name.empty())
		name = "state";

	HelpServState* st = nullptr;
	if (obj)
	{
		st = anope_dynamic_static_cast<HelpServState*>(obj);
	}
	else
	{
		auto it = HelpServStateList->find(name);
		if (it != HelpServStateList->end())
			st = it->second;
		if (!st)
			st = new HelpServState();
	}

	st->name = name;
	data.TryLoad("next_ticket_id", st->next_ticket_id);

	data.TryLoad("help_requests", st->help_requests);
	data.TryLoad("search_requests", st->search_requests);
	data.TryLoad("search_hits", st->search_hits);
	data.TryLoad("search_misses", st->search_misses);
	data.TryLoad("unknown_topics", st->unknown_topics);
	data.TryLoad("helpme_requests", st->helpme_requests);
	data.TryLoad("request_requests", st->request_requests);
	data.TryLoad("cancel_requests", st->cancel_requests);
	data.TryLoad("list_requests", st->list_requests);
	data.TryLoad("next_requests", st->next_requests);
	data.TryLoad("view_requests", st->view_requests);
	data.TryLoad("take_requests", st->take_requests);
	data.TryLoad("assign_requests", st->assign_requests);
	data.TryLoad("note_requests", st->note_requests);
	data.TryLoad("close_requests", st->close_requests);
	data.TryLoad("priority_requests", st->priority_requests);
	data.TryLoad("wait_requests", st->wait_requests);
	data.TryLoad("unwait_requests", st->unwait_requests);
	data.TryLoad("notify_requests", st->notify_requests);

	uint64_t topiccount = 0;
	data.TryLoad("topiccount", topiccount);
	st->topic_requests.clear();
	for (uint64_t idx = 0; idx < topiccount; ++idx)
	{
		const Anope::string prefix = "topic" + Anope::ToString(idx) + ".";
		Anope::string topic;
		uint64_t count = 0;
		data.TryLoad(prefix + "name", topic);
		data.TryLoad(prefix + "count", count);
		if (!topic.empty())
			st->topic_requests[topic] = count;
	}

	uint64_t hc = 0;
	data.TryLoad("helpme_cooldown_count", hc);
	st->last_helpme_by_key.clear();
	for (uint64_t idx = 0; idx < hc; ++idx)
	{
		const Anope::string prefix = "helpme_cooldown" + Anope::ToString(idx) + ".";
		Anope::string k;
		time_t ts = 0;
		data.TryLoad(prefix + "key", k);
		data.TryLoad(prefix + "ts", ts);
		if (!k.empty() && ts > 0)
			st->last_helpme_by_key[k] = ts;
	}

	uint64_t rc = 0;
	data.TryLoad("request_cooldown_count", rc);
	st->last_request_by_key.clear();
	for (uint64_t idx = 0; idx < rc; ++idx)
	{
		const Anope::string prefix = "request_cooldown" + Anope::ToString(idx) + ".";
		Anope::string k;
		time_t ts = 0;
		data.TryLoad(prefix + "key", k);
		data.TryLoad(prefix + "ts", ts);
		if (!k.empty() && ts > 0)
			st->last_request_by_key[k] = ts;
	}

	if (!st->next_ticket_id)
		st->next_ticket_id = 1;

	return st;
}

Anope::string HelpServCore::NormalizeTopic(const Anope::string& in)
{
	Anope::string out = in;
	out.trim();
	out = out.lower();
	return out;
}

int HelpServCore::ClampPriority(int p)
{
	if (p < 0)
		return 0;
	if (p > 2)
		return 2;
	return p;
}

Anope::string HelpServCore::PriorityString(int p)
{
	switch (ClampPriority(p))
	{
		case 0: return "low";
		case 2: return "high";
		default: return "normal";
	}
}

bool HelpServCore::ParsePriority(const Anope::string& in, int& out)
{
	Anope::string s = in;
	s.trim();
	if (s.empty())
		return false;
	if (s.equals_ci("low"))
	{
		out = 0;
		return true;
	}
	if (s.equals_ci("normal") || s.equals_ci("med") || s.equals_ci("medium"))
	{
		out = 1;
		return true;
	}
	if (s.equals_ci("high"))
	{
		out = 2;
		return true;
	}

	bool all_digits = true;
	for (size_t i = 0; i < s.length(); ++i)
		if (s[i] < '0' || s[i] > '9')
			all_digits = false;
	if (!all_digits)
		return false;
	uint64_t n = 0;
	if (!ParseU64(s, n))
		return false;
	out = ClampPriority(static_cast<int>(n));
	return true;
}

int HelpServCore::StateSortKey(const Anope::string& state)
{
	if (state.equals_ci("waiting") || state.equals_ci("wait"))
		return 1;
	return 0;
}

Anope::string HelpServCore::NormalizeState(const Anope::string& state)
{
	if (state.equals_ci("waiting") || state.equals_ci("wait"))
		return "waiting";
	return "open";
}

bool HelpServCore::TicketMatchesFilter(const HelpServTicket& t, const Anope::string& filter)
{
	if (filter.empty())
		return true;
	const auto match = ContainsCaseInsensitive;
	if (match(t.nick, filter) || match(t.account, filter) || match(t.topic, filter)
		|| match(t.message, filter) || match(t.requester, filter) || match(t.assigned, filter)
		|| match(t.state, filter) || match(t.wait_reason, filter))
		return true;
	return false;
}

std::vector<HelpServTicket*> HelpServCore::GetSortedTickets(const Anope::string& filter, bool include_waiting)
{
	std::vector<HelpServTicket*> out;
	out.reserve(HelpServTicketList->size());
	for (const auto& it : *HelpServTicketList)
	{
		HelpServTicket* t = it.second;
		if (!t)
			continue;
		if (!TicketMatchesFilter(*t, filter))
			continue;
		if (!include_waiting && NormalizeState(t->state).equals_ci("waiting"))
			continue;
		out.push_back(t);
	}
	std::sort(out.begin(), out.end(), [](const HelpServTicket* a, const HelpServTicket* b) {
		const int as = StateSortKey(a->state);
		const int bs = StateSortKey(b->state);
		if (as != bs)
			return as < bs;
		const int ap = ClampPriority(a->priority);
		const int bp = ClampPriority(b->priority);
		if (ap != bp)
			return ap > bp;
		const auto at = (a->updated ? a->updated : a->created);
		const auto bt = (b->updated ? b->updated : b->created);
		if (at != bt)
			return at < bt;
		return a->id < b->id;
	});
	return out;
}

void HelpServCore::Reply(CommandSource& source, const Anope::string& msg)
{
	if (!this->HelpServ.operator bool())
	{
		source.Reply("%s", msg.c_str());
		return;
	}

	User* u = source.GetUser();
	if (!u)
	{
		source.Reply("%s", msg.c_str());
		return;
	}

	Anope::map<Anope::string> tags;
	if (!source.msgid.empty())
		tags["+draft/reply"] = source.msgid;

	LineWrapper lw(Language::Translate(u, msg.c_str()));
	for (Anope::string line; lw.GetLine(line); )
	{
		if (this->reply_with_notice)
			IRCD->SendNotice(*this->HelpServ, u->GetUID(), line, tags);
		else
			IRCD->SendPrivmsg(*this->HelpServ, u->GetUID(), line, tags);
	}
}

void HelpServCore::SendToUser(User* u, const Anope::string& msg)
{
	if (!this->HelpServ.operator bool() || !u)
		return;

	Anope::map<Anope::string> tags;
	LineWrapper lw(Language::Translate(u, msg.c_str()));
	for (Anope::string line; lw.GetLine(line); )
	{
		if (this->reply_with_notice)
			IRCD->SendNotice(*this->HelpServ, u->GetUID(), line, tags);
		else
			IRCD->SendPrivmsg(*this->HelpServ, u->GetUID(), line, tags);
	}
}

void HelpServCore::Reply(CommandSource& source, const char* text)
{
	this->Reply(source, Anope::string(text));
}

void HelpServCore::ReplyF(CommandSource& source, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	Anope::string msg = Anope::Format(args, fmt);
	va_end(args);
	this->Reply(source, msg);
}

Anope::string HelpServCore::ReplyModeString() const
{
	return this->reply_with_notice ? "notice" : "privmsg";
}

bool HelpServCore::SetReplyMode(const Anope::string& mode)
{
	if (mode.equals_ci("notice"))
	{
		this->reply_with_notice = true;
		return true;
	}
	if (mode.equals_ci("privmsg") || mode.equals_ci("msg"))
	{
		this->reply_with_notice = false;
		return true;
	}
	return false;
}

void HelpServCore::SendIndex(CommandSource& source)
{
	this->Reply(source, "Hi! I'm HelpServ. Try: \002HELP\002 or \002HELP <topic>\002");
	this->Reply(source, "You can also try: \002SEARCH <words>\002");
	this->Reply(source, "Need staff? Try: \002HELPME <topic> [message]\002 or \002REQUEST <topic> [message]\002");

	if (this->topics.empty())
	{
		this->Reply(source, "No help topics are configured.");
		return;
	}

	Anope::string topic_list;
	for (const auto& [name, _] : this->topics)
	{
		if (!topic_list.empty())
			topic_list += ", ";
		topic_list += name;
	}

	this->ReplyF(source, "Available topics: %s", topic_list.c_str());
}

bool HelpServCore::SendTopic(CommandSource& source, const Anope::string& topic_key)
{
	auto it = this->topics.find(topic_key);
	if (it == this->topics.end())
		return false;

	this->ReplyF(source, "Help for \002%s\002:", topic_key.c_str());
	for (const auto& line : it->second)
		this->Reply(source, line);
	return true;
}

bool HelpServCore::ContainsCaseInsensitive(const Anope::string& haystack, const Anope::string& needle)
{
	if (needle.empty())
		return true;
	return haystack.lower().find(needle.lower()) != Anope::string::npos;
}

void HelpServCore::SendStats(CommandSource& source)
{
	auto* st = this->state;
	if (!st)
	{
		this->Reply(source, "HelpServ state is not initialized.");
		return;
	}

	size_t line_count = 0;
	for (const auto& [_, lines] : this->topics)
		line_count += lines.size();

	this->Reply(source, "HelpServ stats:");
	this->ReplyF(source, "Topics: %zu, Lines: %zu", this->topics.size(), line_count);
	this->ReplyF(source, "HELP requests: %llu (unknown topics: %llu)",
		static_cast<unsigned long long>(st->help_requests),
		static_cast<unsigned long long>(st->unknown_topics));
	this->ReplyF(source, "SEARCH requests: %llu (hits: %llu, misses: %llu)",
		static_cast<unsigned long long>(st->search_requests),
		static_cast<unsigned long long>(st->search_hits),
		static_cast<unsigned long long>(st->search_misses));
	this->ReplyF(source, "Tickets cmd usage: REQUEST %llu, CANCEL %llu, LIST %llu, NEXT %llu, VIEW %llu",
		static_cast<unsigned long long>(st->request_requests),
		static_cast<unsigned long long>(st->cancel_requests),
		static_cast<unsigned long long>(st->list_requests),
		static_cast<unsigned long long>(st->next_requests),
		static_cast<unsigned long long>(st->view_requests));
	this->ReplyF(source, "Staff cmd usage: TAKE %llu, ASSIGN %llu, NOTE %llu, CLOSE %llu, PRIORITY %llu, WAIT %llu, UNWAIT %llu",
		static_cast<unsigned long long>(st->take_requests),
		static_cast<unsigned long long>(st->assign_requests),
		static_cast<unsigned long long>(st->note_requests),
		static_cast<unsigned long long>(st->close_requests),
		static_cast<unsigned long long>(st->priority_requests),
		static_cast<unsigned long long>(st->wait_requests),
		static_cast<unsigned long long>(st->unwait_requests));
	this->ReplyF(source, "Other cmd usage: HELPME %llu, NOTIFY %llu",
		static_cast<unsigned long long>(st->helpme_requests),
		static_cast<unsigned long long>(st->notify_requests));

	if (!st->topic_requests.empty())
	{
		// Show top 5 topics.
		std::vector<std::pair<Anope::string, uint64_t>> top;
		top.reserve(st->topic_requests.size());
		for (const auto& kv : st->topic_requests)
			top.push_back(kv);
		std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
			return a.second > b.second;
		});

		Anope::string buf;
		size_t shown = 0;
		for (const auto& [name, count] : top)
		{
			if (shown++ >= 5)
				break;
			if (!buf.empty())
				buf += ", ";
			buf += Anope::Format("%s(%llu)", name.c_str(), static_cast<unsigned long long>(count));
		}
		if (!buf.empty())
			this->ReplyF(source, "Top topics: %s", buf.c_str());
	}

	this->PruneExpiredTickets();
	const auto now = Anope::CurTime;
	if (!HelpServTicketList->empty())
	{
		size_t open = 0;
		size_t waiting = 0;
		size_t assigned = 0;
		size_t pri_low = 0;
		size_t pri_normal = 0;
		size_t pri_high = 0;

		uint64_t oldest_open_id = 0;
		time_t oldest_open_created = 0;
		time_t oldest_open_updated = 0;
		uint64_t oldest_wait_id = 0;
		time_t oldest_wait_created = 0;
		time_t oldest_wait_updated = 0;

		std::map<Anope::string, uint64_t> ticket_topics;
		auto consider_oldest = [&](bool is_waiting, const HelpServTicket& t) {
			const auto created = t.created;
			if (!created)
				return;
			uint64_t& oldest_id = is_waiting ? oldest_wait_id : oldest_open_id;
			time_t& oldest_created = is_waiting ? oldest_wait_created : oldest_open_created;
			time_t& oldest_updated = is_waiting ? oldest_wait_updated : oldest_open_updated;
			if (!oldest_created || created < oldest_created)
			{
				oldest_id = t.id;
				oldest_created = created;
				oldest_updated = t.updated;
			}
		};

		for (const auto& it : *HelpServTicketList)
		{
			const auto* tp = it.second;
			if (!tp)
				continue;
			const auto& t = *tp;
			const auto state = NormalizeState(t.state);
			const bool is_waiting = state.equals_ci("waiting");
			if (is_waiting)
				++waiting;
			else
				++open;

			if (!t.assigned.empty())
				++assigned;

			switch (ClampPriority(t.priority))
			{
				case 0: ++pri_low; break;
				case 2: ++pri_high; break;
				default: ++pri_normal; break;
			}

			if (!t.topic.empty())
				++ticket_topics[t.topic];

			consider_oldest(is_waiting, t);
		}

		this->ReplyF(source, "Tickets: %zu (open: %zu, waiting: %zu)", HelpServTicketList->size(), open, waiting);
		this->ReplyF(source, "Tickets by priority: high: %zu, normal: %zu, low: %zu", pri_high, pri_normal, pri_low);
		this->ReplyF(source, "Tickets assigned: %zu (unassigned: %zu)", assigned, HelpServTicketList->size() - assigned);

		auto age = [&](time_t when) {
			if (!when || now <= when)
				return Anope::string("0s");
			return Anope::Duration(now - when, source.GetAccount());
		};
		if (oldest_open_id)
			this->ReplyF(source, "Oldest open ticket: \002#%llu\002 (created %s ago%s)",
				static_cast<unsigned long long>(oldest_open_id),
				age(oldest_open_created).c_str(),
				oldest_open_updated ? Anope::Format(", updated %s ago", age(oldest_open_updated).c_str()).c_str() : "");
		if (oldest_wait_id)
			this->ReplyF(source, "Oldest waiting ticket: \002#%llu\002 (created %s ago%s)",
				static_cast<unsigned long long>(oldest_wait_id),
				age(oldest_wait_created).c_str(),
				oldest_wait_updated ? Anope::Format(", updated %s ago", age(oldest_wait_updated).c_str()).c_str() : "");

		if (!ticket_topics.empty())
		{
			std::vector<std::pair<Anope::string, uint64_t>> top;
			top.reserve(ticket_topics.size());
			for (const auto& kv : ticket_topics)
				top.push_back(kv);
			std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
				return a.second > b.second;
			});

			Anope::string buf;
			size_t shown = 0;
			for (const auto& [name, count] : top)
			{
				if (shown++ >= 5)
					break;
				if (!buf.empty())
					buf += ", ";
				buf += Anope::Format("%s(%llu)", name.c_str(), static_cast<unsigned long long>(count));
			}
			if (!buf.empty())
				this->ReplyF(source, "Ticket topics: %s", buf.c_str());
		}
	}

	if (this->last_reload)
		this->ReplyF(source, "Last reload: %s", Anope::strftime(this->last_reload, source.GetAccount()).c_str());
}

bool HelpServCore::ParseU64(const Anope::string& in, uint64_t& out)
{
	try
	{
		out = Anope::Convert<uint64_t>(in, 0);
		return true;
	}
	catch (...)
	{
		out = 0;
		return false;
	}
}

bool HelpServCore::TryParseTicketId(const Anope::string& in, uint64_t& out)
{
	Anope::string s = in;
	s.trim();
	if (s.empty())
		return false;
	if (s[0] == '#')
		s = s.substr(1);
	s.trim();
	if (s.empty())
		return false;
	for (size_t i = 0; i < s.length(); ++i)
		if (s[i] < '0' || s[i] > '9')
			return false;
	return ParseU64(s, out) && out != 0;
}

time_t HelpServCore::ParseDurationSeconds(const Anope::string& in, time_t fallback)
{
	Anope::string s = in;
	s.trim();
	if (s.empty())
		return fallback;

	// Pure number = seconds.
	bool all_digits = true;
	for (size_t i = 0; i < s.length(); ++i)
		if (s[i] < '0' || s[i] > '9')
			all_digits = false;
	if (all_digits)
	{
		uint64_t n = 0;
		if (!ParseU64(s, n))
			return fallback;
		return static_cast<time_t>(n);
	}

	// Number + suffix (s/m/h/d/w).
	char suffix = s[s.length() - 1];
	Anope::string num = s.substr(0, s.length() - 1);
	num.trim();
	if (num.empty())
		return fallback;
	for (size_t i = 0; i < num.length(); ++i)
		if (num[i] < '0' || num[i] > '9')
			return fallback;
	uint64_t n = 0;
	if (!ParseU64(num, n))
		return fallback;
	uint64_t mult = 1;
	switch (suffix)
	{
		case 's': case 'S': mult = 1; break;
		case 'm': case 'M': mult = 60; break;
		case 'h': case 'H': mult = 60 * 60; break;
		case 'd': case 'D': mult = 60 * 60 * 24; break;
		case 'w': case 'W': mult = 60 * 60 * 24 * 7; break;
		default: return fallback;
	}
	return static_cast<time_t>(n * mult);
}

HelpServTicket* HelpServCore::FindTicketById(uint64_t id)
{
	if (!id)
		return nullptr;
	auto it = HelpServTicketList->find(TicketKey(id));
	if (it == HelpServTicketList->end())
		return nullptr;
	return it->second;
}

void HelpServCore::PruneExpiredTickets()
{
	if (!this->ticket_expire)
		return;
	const auto now = Anope::CurTime;
	if (now <= 0)
		return;
	const auto cutoff = now - this->ticket_expire;
	std::vector<HelpServTicket*> expired;
	for (const auto& it : *HelpServTicketList)
	{
		HelpServTicket* t = it.second;
		if (!t)
			continue;
		const auto last = t->updated ? t->updated : t->created;
		if (last && last < cutoff)
			expired.push_back(t);
	}
	if (expired.empty())
		return;

	for (auto* t : expired)
		delete t;
	this->ScheduleDBSave();
	Log(this) << "Expired " << expired.size() << " old tickets";
}

void HelpServCore::PruneCooldownMaps(time_t now)
{
	if (now <= 0)
		return;
	auto* st = this->state;
	if (!st)
		return;

	// These maps are only used for rate limiting, but can grow without bound
	// if many unique users hit HELPME/REQUEST over time.
	const size_t total_size = st->last_helpme_by_key.size() + st->last_request_by_key.size();
	const size_t max_size_before_force = static_cast<size_t>(this->cooldown_prune_max_size);
	const time_t prune_interval = this->cooldown_prune_interval;
	const time_t ttl = this->cooldown_prune_ttl;

	if (total_size < max_size_before_force && this->last_cooldown_prune && prune_interval > 0 && now - this->last_cooldown_prune < prune_interval)
		return;

	bool changed = false;
	auto prune_map = [&](auto& m) {
		for (auto it = m.begin(); it != m.end(); )
		{
			const time_t last = it->second;
			if (!last || now - last > ttl)
			{
				it = m.erase(it);
				changed = true;
			}
			else
				++it;
		}
	};

	prune_map(st->last_helpme_by_key);
	prune_map(st->last_request_by_key);
	this->last_cooldown_prune = now;
	if (changed)
		this->MarkStateChanged();
}

class HelpServCore::HelpServDeferredSaveTimer final
	: public Timer
{
	HelpServCore& hs;

public:
	HelpServDeferredSaveTimer(HelpServCore& owner, time_t seconds)
		: Timer(&owner, seconds)
		, hs(owner)
	{
	}

	bool Tick() override
	{
		if (!this->hs.db_save_pending)
			return true;
		if (!Me || !Me->IsSynced())
			return true;
		this->hs.db_save_pending = false;
		Anope::SaveDatabases();
		return true;
	}
};

void HelpServCore::ScheduleDBSave()
{
	if (Anope::ReadOnly)
		return;
	this->db_save_pending = true;
	if (this->db_save_timer)
		return;
	// Coalesce writes: save once within ~5 seconds.
	this->db_save_timer = new HelpServDeferredSaveTimer(*this, 5);
}


void HelpServCore::MarkStateChanged()
{
	if (!this->state)
		return;
	this->state->QueueUpdate();
	this->ScheduleDBSave();
}

void HelpServCore::MarkTicketChanged(HelpServTicket* t)
{
	if (t)
		t->QueueUpdate();
	this->ScheduleDBSave();
}

bool HelpServCore::IsStaff(CommandSource& source) const
{
	return source.HasPriv(this->ticket_priv);
}

Anope::string HelpServCore::GetRequesterKey(CommandSource& source) const
{
	if (source.GetAccount())
		return source.GetAccount()->display;
	if (source.GetUser())
		return source.GetUser()->GetUID();
	return source.GetNick();
}

void HelpServCore::PageStaff(const Anope::string& msg)
{
	if (!this->HelpServ || this->staff_target.empty())
		return;

	if (this->staff_target.equals_ci("globops"))
	{
		IRCD->SendGlobops(*this->HelpServ, msg);
		return;
	}

	if (this->staff_target[0] == '#')
	{
		this->HelpServ->Join(this->staff_target);
		IRCD->SendPrivmsg(*this->HelpServ, this->staff_target, msg);
	}
}

HelpServTicket* HelpServCore::FindOpenTicketByAccountKey(const Anope::string& account_key)
{
	const auto needle = NormalizeTopic(account_key);
	if (needle.empty())
		return nullptr;
	for (const auto& it : *HelpServTicketList)
	{
		HelpServTicket* t = it.second;
		if (!t)
			continue;
		if (!t->account.empty() && NormalizeTopic(t->account) == needle)
			return t;
	}
	return nullptr;
}

HelpServTicket* HelpServCore::FindOpenTicketByNickOrAccount(const Anope::string& who)
{
	// Try account key first.
	if (auto* t = this->FindOpenTicketByAccountKey(who))
		return t;

	// Fall back to nick match.
	for (const auto& it : *HelpServTicketList)
	{
		HelpServTicket* t = it.second;
		if (t && t->nick.equals_ci(who))
			return t;
	}
	return nullptr;
}

void HelpServCore::NotifyTicketEvent(const Anope::string& msg)
{
	this->PageStaff(msg);
	Log(this) << msg;
}

void HelpServCore::Search(CommandSource& source, const Anope::string& query)
{
	if (this->state)
	{
		++this->state->search_requests;
		this->MarkStateChanged();
	}
	Anope::string q = query;
	q.trim();
	if (q.empty())
	{
		this->Reply(source, "What should I search for? Try: \002SEARCH vhost\002");
		return;
	}

	std::vector<Anope::string> matches;
	for (const auto& [name, lines] : this->topics)
	{
		if (ContainsCaseInsensitive(name, q))
		{
			matches.push_back(name);
			continue;
		}
		for (const auto& line : lines)
		{
			if (ContainsCaseInsensitive(line, q))
			{
				matches.push_back(name);
				break;
			}
		}
	}

	if (matches.empty())
	{
		if (this->state)
		{
			++this->state->search_misses;
			this->MarkStateChanged();
		}
		this->ReplyF(source, "No topics matched \002%s\002.", q.c_str());
		this->Reply(source, "Try: \002HELP\002 to list topics.");
		return;
	}

	if (this->state)
	{
		++this->state->search_hits;
		this->MarkStateChanged();
	}
	std::sort(matches.begin(), matches.end());

	const size_t limit = 10;
	Anope::string out;
	for (size_t i = 0; i < matches.size() && i < limit; ++i)
	{
		if (!out.empty())
			out += ", ";
		out += matches[i];
	}
	this->ReplyF(source, "Matches: %s", out.c_str());
	if (matches.size() > limit)
		this->ReplyF(source, "(%zu more not shown)", matches.size() - limit);
	this->Reply(source, "Use: \002HELP <topic>\002");
}

void HelpServCore::LoadTopics(const Configuration::Block& mod)
{
	this->topics.clear();
	bool state_changed = false;

	const int topic_count = mod.CountBlock("topic");
	for (int i = 0; i < topic_count; ++i)
	{
		const auto& topic_block = mod.GetBlock("topic", i);
		Anope::string topic_name = NormalizeTopic(topic_block.Get<const Anope::string>("name"));
		if (topic_name.empty())
			continue;

		std::vector<Anope::string> lines;
		const int line_count = topic_block.CountBlock("line");
		for (int j = 0; j < line_count; ++j)
		{
			const auto& line_block = topic_block.GetBlock("line", j);
			Anope::string text = line_block.Get<const Anope::string>("text");
			text.trim();
			if (!text.empty())
				lines.push_back(text);
		}

		if (!lines.empty())
		{
			if (this->state)
			{
				auto it = this->state->topic_requests.find(topic_name);
				if (it == this->state->topic_requests.end())
				{
					this->state->topic_requests.emplace(topic_name, 0);
					state_changed = true;
				}
			}
			this->topics.emplace(std::move(topic_name), std::move(lines));
		}
	}

	if (state_changed)
		this->MarkStateChanged();
}

HelpServCore::HelpServCore(const Anope::string& modname, const Anope::string& creator)
	: Module(modname, creator, PSEUDOCLIENT | THIRD)
	, ticket_type(this)
	, state_type(this)
	, command_search(this, *this)
	, command_stats(this, *this)
	, command_helpme(this, *this)
	, command_request(this, *this)
	, command_cancel(this, *this)
	, command_list(this, *this)
	, command_close(this, *this)
	, command_take(this, *this)
	, command_assign(this, *this)
	, command_note(this, *this)
	, command_view(this, *this)
	, command_next(this, *this)
	, command_priority(this, *this)
	, command_wait(this, *this)
	, command_unwait(this, *this)
	, command_notify(this, *this)
{
	if (!IRCD)
		throw ModuleException("IRCd protocol module not loaded");
}

HelpServCore::~HelpServCore()
{
	this->db_save_pending = false;
	this->db_save_timer = nullptr;
}

void HelpServCore::OnReload(Configuration::Conf& conf)
{
	// Ensure we have a persistent state record.
	auto it = HelpServStateList->find("state");
	if (it != HelpServStateList->end())
		this->state = it->second;
	if (!this->state)
		this->state = new HelpServState();
	this->state->name = "state";
	if (!this->state->next_ticket_id)
		this->state->next_ticket_id = 1;

	const Configuration::Block* mod = &conf.GetModule(this);
	Anope::string nick = mod->Get<const Anope::string>("client");
	if (nick.empty())
	{
		mod = &conf.GetModule("helpserv");
		nick = mod->Get<const Anope::string>("client");
	}
	if (nick.empty())
	{
		mod = &conf.GetModule("helpserv.so");
		nick = mod->Get<const Anope::string>("client");
	}
	if (nick.empty())
		throw ConfigException(Module::name + ": <client> must be defined");

	BotInfo* bi = BotInfo::Find(nick, true);
	if (!bi)
		throw ConfigException(Module::name + ": no bot named " + nick);

	this->HelpServ = bi;
	this->last_reload = Anope::CurTime;

	// Escalation/ticket configuration.
	this->staff_target = mod->Get<Anope::string>("staff_target", "");
	this->helpme_cooldown = mod->Get<time_t>("helpme_cooldown", "120");
	this->request_cooldown = mod->Get<time_t>("request_cooldown", "60");
	this->cooldown_prune_interval = ParseDurationSeconds(mod->Get<Anope::string>("cooldown_prune_interval", "1h"), 60 * 60);
	this->cooldown_prune_ttl = ParseDurationSeconds(mod->Get<Anope::string>("cooldown_prune_ttl", "24h"), 60 * 60 * 24);
	{
		uint64_t max_size = 0;
		if (ParseU64(mod->Get<Anope::string>("cooldown_prune_max_size", "5000"), max_size) && max_size)
			this->cooldown_prune_max_size = max_size;
		else
			this->cooldown_prune_max_size = 5000;
	}
	this->page_on_request = mod->Get<bool>("page_on_request", "yes");
	this->ticket_priv = mod->Get<Anope::string>("ticket_priv", "helpserv/ticket");
	this->ticket_expire = ParseDurationSeconds(mod->Get<Anope::string>("ticket_expire", "0"), 0);
	this->notify_priv = mod->Get<Anope::string>("notify_priv", "helpserv/admin");
	this->SetReplyMode(mod->Get<Anope::string>("reply_method", "notice"));

	if (!this->staff_target.empty() && this->staff_target[0] == '#')
		this->HelpServ->Join(this->staff_target);

	this->PruneExpiredTickets();

	this->LoadTopics(*mod);

	// Ensure the db backend writes helpserv.module.json.
	this->MarkStateChanged();
}

EventReturn HelpServCore::OnBotPrivmsg(User* u, BotInfo* bi, Anope::string& message, const Anope::map<Anope::string>& tags)
{
	if (bi != *this->HelpServ || !u)
		return EVENT_CONTINUE;

	Anope::string trimmed = message;
	trimmed.trim();
	if (trimmed.empty())
		return EVENT_CONTINUE;

	// Let users type "help ..." in any case; normalize it to HELP so generic/help routing works.
	if (trimmed.length() >= 4 && trimmed.substr(0, 4).equals_ci("help"))
	{
		message = "HELP" + trimmed.substr(4);
	}

	return EVENT_CONTINUE;
}

EventReturn HelpServCore::OnPreHelp(CommandSource& source, const std::vector<Anope::string>& params)
{
	if (!this->HelpServ || source.service != *this->HelpServ)
		return EVENT_CONTINUE;

	if (this->state)
	{
		++this->state->help_requests;
		this->MarkStateChanged();
	}

	if (params.empty())
	{
		this->SendIndex(source);
		return EVENT_STOP;
	}

	const Anope::string topic_key = NormalizeTopic(params[0]);
	if (!topic_key.empty() && this->SendTopic(source, topic_key))
	{
		if (this->state)
		{
			++this->state->topic_requests[topic_key];
			this->MarkStateChanged();
		}
		return EVENT_STOP;
	}

	if (this->state)
	{
		++this->state->unknown_topics;
		this->MarkStateChanged();
	}
	this->Reply(source, "I don't know that topic. Try: \002HELP\002 or \002SEARCH <words>\002");
	return EVENT_STOP;
}
