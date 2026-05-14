/*
m_apiauth.cpp
2025 Jean "reverse" Chevronnet
Module for Anope IRC Services v2.1, lets users authenticate with
credentials stored in an external API endpoint instead of the internal
Anope database.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License.

/// $LinkerFlags:  -lcrypto -lssl -lcurl -lnlohmann_json
/// BEGIN CMAKE
/// find_package(OpenSSL REQUIRED)
/// find_package(CURL REQUIRED)
/// target_link_libraries(${SO} PUBLIC OpenSSL::Crypto OpenSSL::SSL CURL::libcurl)
/// END CMAKE
*/

#include "module.h"
#include "serialize.h"
#include "modules/encryption.h"
#include "modules/nickserv/sasl.h"
#include "modules/sasl_scram.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>  // Added for JWT token decoding and verification

#include <memory>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// Global module reference
static Module *me;

// For convenience
using json = nlohmann::json;

namespace
{
    // SCRAM-SHA-512 helpers (RFC5802/RFC7677). Kept local to this module so
    // SASL SCRAM-SHA-512 support can ship as an add-on to m_apiauth.
    constexpr size_t SCRAM_SHA512_LEN = 64;
    constexpr size_t SCRAM_SHA256_LEN = 32;

    Anope::string RandomBytes(size_t len);

    Anope::string B64EncodeNoPad(const Anope::string &raw)
    {
        auto b64 = Anope::B64Encode(raw);
        // Some SCRAM client implementations appear to mishandle '=' padding
        // inside the decoded SCRAM attribute values (s= / v=). Padding is not
        // semantically significant for base64 decoding, so strip it.
        while (b64.length() > 0 && b64[b64.length() - 1] == '=')
            b64.erase(b64.length() - 1);
        return b64;
    }

    Anope::string ScramAttrB64Encode(const Anope::string &raw, bool no_padding)
    {
        return no_padding ? B64EncodeNoPad(raw) : Anope::B64Encode(raw);
    }

    struct SaslAuthAssembleResult final
    {
        bool complete = false;
        bool empty = false;
        size_t appended = 0;
    };

    SaslAuthAssembleResult AssembleSaslAuthenticateData(const std::vector<Anope::string> &parts, Anope::string &pending_b64)
    {
        // RFC 4616/IRCv3 SASL framing:
        // - base64 is sent in 400-byte chunks.
        // - if the last chunk is exactly 400 bytes, the sender MUST send an extra "AUTHENTICATE +" to terminate.
        // - a bare "+" can also represent an empty response.
        SaslAuthAssembleResult res;
        if (parts.empty())
            return res;

        for (const auto &part : parts)
        {
            if (part == "+")
            {
                res.complete = true;
                res.empty = pending_b64.empty();
                continue;
            }

            pending_b64 += part;
            res.appended += part.length();
        }

        // If no explicit terminator was present, a final chunk shorter than 400 completes the message.
        if (!res.complete)
        {
            const auto &last = parts.back();
            if (last != "+" && last.length() < 400)
                res.complete = true;
        }

        return res;
    }

    Anope::string MakeScramServerNonce(size_t bytes)
    {
        // Nonce is an opaque, printable string (must not contain commas).
        // Some IRC clients appear to choke on '+' and '/' in SCRAM values;
        // use hex to keep the nonce strictly [0-9a-f], which is always safe.
        const auto raw = RandomBytes(bytes);
        if (raw.empty())
            return {};
        return Anope::Hex(raw);
    }

    bool ConstantTimeEquals(const Anope::string &a, const Anope::string &b)
    {
        if (a.length() != b.length())
            return false;

        unsigned char diff = 0;
        for (size_t i = 0; i < a.length(); ++i)
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        return diff == 0;
    }

    Anope::string RandomBytes(size_t len)
    {
        Anope::string out;
        out.resize(len);
        if (len && RAND_bytes(reinterpret_cast<unsigned char *>(&out[0]), static_cast<int>(len)) != 1)
            return {};
        return out;
    }

    Anope::string Sha512(const Anope::string &data)
    {
        unsigned char md[SCRAM_SHA512_LEN];
        unsigned int md_len = 0;
        if (!EVP_Digest(reinterpret_cast<const unsigned char *>(data.data()), data.length(), md, &md_len, EVP_sha512(), nullptr) || md_len != SCRAM_SHA512_LEN)
            return {};
        return Anope::string(reinterpret_cast<const char *>(md), md_len);
    }

    Anope::string Sha256(const Anope::string &data)
    {
        unsigned char md[SCRAM_SHA256_LEN];
        unsigned int md_len = 0;
        if (!EVP_Digest(reinterpret_cast<const unsigned char *>(data.data()), data.length(), md, &md_len, EVP_sha256(), nullptr) || md_len != SCRAM_SHA256_LEN)
            return {};
        return Anope::string(reinterpret_cast<const char *>(md), md_len);
    }

    Anope::string HmacSha512(const Anope::string &key, const Anope::string &data)
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (!HMAC(EVP_sha512(), key.data(), static_cast<int>(key.length()), reinterpret_cast<const unsigned char *>(data.data()), data.length(), md, &md_len) || md_len != SCRAM_SHA512_LEN)
            return {};
        return Anope::string(reinterpret_cast<const char *>(md), md_len);
    }

    Anope::string HmacSha256(const Anope::string &key, const Anope::string &data)
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.length()), reinterpret_cast<const unsigned char *>(data.data()), data.length(), md, &md_len) || md_len != SCRAM_SHA256_LEN)
            return {};
        return Anope::string(reinterpret_cast<const char *>(md), md_len);
    }

    Anope::string Pbkdf2Sha512(const Anope::string &password, const Anope::string &salt, unsigned iterations)
    {
        if (!iterations)
            return {};

        unsigned char out[SCRAM_SHA512_LEN];
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
            reinterpret_cast<const unsigned char *>(salt.data()), static_cast<int>(salt.length()),
            static_cast<int>(iterations), EVP_sha512(), SCRAM_SHA512_LEN, out) != 1)
            return {};

        return Anope::string(reinterpret_cast<const char *>(out), SCRAM_SHA512_LEN);
    }

    Anope::string Pbkdf2Sha256(const Anope::string &password, const Anope::string &salt, unsigned iterations)
    {
        if (!iterations)
            return {};

        unsigned char out[SCRAM_SHA256_LEN];
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
            reinterpret_cast<const unsigned char *>(salt.data()), static_cast<int>(salt.length()),
            static_cast<int>(iterations), EVP_sha256(), SCRAM_SHA256_LEN, out) != 1)
            return {};

        return Anope::string(reinterpret_cast<const char *>(out), SCRAM_SHA256_LEN);
    }

    Anope::string XorSameLength(const Anope::string &a, const Anope::string &b)
    {
        if (a.length() != b.length())
            return {};

        Anope::string out;
        out.resize(a.length());
        for (size_t i = 0; i < a.length(); ++i)
            out[i] = static_cast<char>(static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
        return out;
    }

    // RFC 5802 name escaping.
    Anope::string ScramUnescape(const Anope::string &in)
    {
        Anope::string out;
        for (size_t i = 0; i < in.length(); ++i)
        {
            if (in[i] != '=')
            {
                out.push_back(in[i]);
                continue;
            }

            if (i + 2 >= in.length())
                return {};

            const auto a = in[i + 1];
            const auto b = in[i + 2];
            if (a == '2' && b == 'C')
                out.push_back(',');
            else if (a == '3' && b == 'D')
                out.push_back('=');
            else
                return {};
            i += 2;
        }
        return out;
    }

    struct ScramFields final
    {
        Anope::string username;
        Anope::string nonce;
        Anope::string channel_binding;
        Anope::string proof_b64;
    };

    bool SplitCommaAttrs(const Anope::string &s, Anope::map<Anope::string> &out)
    {
        out.clear();
        std::vector<Anope::string> parts;
        parts.clear();
        Anope::string cur;
        for (char ch : s)
        {
            if (ch == ',')
            {
                parts.push_back(cur);
                cur.clear();
            }
            else
                cur.push_back(ch);
        }
        parts.push_back(cur);

        for (const auto &p : parts)
        {
            if (p.empty())
                continue;
            auto eq = p.find('=');
            if (eq == Anope::string::npos)
                return false;
            Anope::string k = p.substr(0, eq);
            Anope::string v = p.substr(eq + 1);
            out[k] = v;
        }
        return true;
    }

    bool ParseClientFirstMessage(const Anope::string &decoded, ScramFields &out, Anope::string &client_first_bare, Anope::string &gs2_header)
    {
        // Expected: gs2-header + client-first-message-bare
        if (decoded.length() < 3)
            return false;

        auto comma1 = decoded.find(',');
        if (comma1 == Anope::string::npos)
            return false;
        auto comma2 = decoded.find(',', comma1 + 1);
        if (comma2 == Anope::string::npos)
            return false;

        const auto gs2_cbind_flag = decoded.substr(0, comma1);
        if (!gs2_cbind_flag.equals_ci("n") && !gs2_cbind_flag.equals_ci("y"))
            return false;

        // gs2-header is everything up to and including the second comma.
        // Example: "n,," or "y,," or "n,a=authzid,"
        gs2_header = decoded.substr(0, comma2 + 1);

        // authzid field (between comma1 and comma2) must be empty or match authcid.
        const auto authzid_field = decoded.substr(comma1 + 1, comma2 - comma1 - 1);

        client_first_bare = decoded.substr(comma2 + 1);
        Anope::map<Anope::string> attrs;
        if (!SplitCommaAttrs(client_first_bare, attrs))
            return false;

        if (!attrs.count("n") || !attrs.count("r"))
            return false;

        out.username = ScramUnescape(attrs["n"]);
        out.nonce = attrs["r"];
        if (out.username.empty() || out.nonce.empty())
            return false;

        if (!authzid_field.empty())
        {
            if (authzid_field.find_first_of("\r\n\0") != Anope::string::npos)
                return false;
            if (authzid_field.length() < 2 || authzid_field.substr(0, 2) != "a=")
                return false;
            const auto authzid = ScramUnescape(authzid_field.substr(2));
            if (authzid.empty() || authzid != out.username)
                return false;
        }

        if (out.username.find_first_of("\r\n\0") != Anope::string::npos)
            return false;
        if (out.nonce.find_first_of("\r\n\0") != Anope::string::npos)
            return false;

        return true;
    }

    bool ParseClientFinalMessage(const Anope::string &decoded, ScramFields &out, Anope::string &client_final_wo_proof)
    {
        // IMPORTANT: The SCRAM auth_message includes the *exact*
        // client-final-message-without-proof (RFC5802), which may include
        // extensions beyond c= and r=. Preserve ordering and any extra
        // attributes exactly as sent (except p=), otherwise proof validation
        // will fail for clients that include extensions.

        out.channel_binding.clear();
        out.nonce.clear();
        out.proof_b64.clear();
        client_final_wo_proof.clear();

        std::vector<Anope::string> parts;
        parts.clear();
        Anope::string cur;
        for (char ch : decoded)
        {
            if (ch == ',')
            {
                parts.push_back(cur);
                cur.clear();
            }
            else
                cur.push_back(ch);
        }
        parts.push_back(cur);

        bool saw_p = false;
        bool first_out = true;

        for (const auto &p : parts)
        {
            if (p.empty())
                continue;

            auto eq = p.find('=');
            if (eq == Anope::string::npos)
                return false;

            const auto k = p.substr(0, eq);
            const auto v = p.substr(eq + 1);
            if (k == "c")
                out.channel_binding = v;
            else if (k == "r")
                out.nonce = v;
            else if (k == "p")
            {
                if (saw_p)
                    return false;
                out.proof_b64 = v;
                saw_p = true;
                continue; // omit p= from client-final-message-without-proof
            }

            if (!first_out)
                client_final_wo_proof += ",";
            client_final_wo_proof += p;
            first_out = false;
        }

        if (!saw_p)
            return false;
        if (out.channel_binding.empty() || out.nonce.empty() || out.proof_b64.empty())
            return false;
        if (client_final_wo_proof.empty())
            return false;

        return true;
    }

    struct ScramVerifier final
    {
        unsigned iterations = 0;
        Anope::string salt;       // raw bytes
        Anope::string stored_key; // raw bytes (SHA512)
        Anope::string server_key; // raw bytes (SHA512)
    };

    bool ParseVerifier(const Anope::string &encoded, ScramVerifier &out)
    {
        Anope::map<Anope::string> attrs;
        if (!SplitCommaAttrs(encoded, attrs))
            return false;

        if (!attrs.count("v") || attrs["v"] != "1")
            return false;
        if (!attrs.count("i") || !attrs.count("s") || !attrs.count("sk") || !attrs.count("sv"))
            return false;

        out.iterations = static_cast<unsigned>(Anope::Convert<unsigned>(attrs["i"], 0));
        if (!out.iterations)
            return false;

        out.salt = Anope::B64Decode(attrs["s"]);
        out.stored_key = Anope::B64Decode(attrs["sk"]);
        out.server_key = Anope::B64Decode(attrs["sv"]);

        if (out.salt.empty() || out.stored_key.length() != SCRAM_SHA512_LEN || out.server_key.length() != SCRAM_SHA512_LEN)
            return false;

        return true;
    }

    Anope::string EncodeVerifier(const ScramVerifier &v)
    {
        return "v=1,i=" + Anope::ToString(v.iterations)
            + ",s=" + Anope::B64Encode(v.salt)
            + ",sk=" + Anope::B64Encode(v.stored_key)
            + ",sv=" + Anope::B64Encode(v.server_key);
    }

    bool MakeVerifier(const Anope::string &password, unsigned iterations, size_t salt_len, ScramVerifier &out)
    {
        out = {};
        out.iterations = iterations;
        // Some clients incorrectly mishandle '+' or '/' in the base64 salt.
        // Keep generating until the *standard* base64 encoding avoids those chars.
        bool found_safe_salt = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt)
        {
            out.salt = RandomBytes(salt_len);
            if (out.salt.empty())
                return false;

            const auto salt_b64 = Anope::B64Encode(out.salt);
            if (salt_b64.find('+') == Anope::string::npos && salt_b64.find('/') == Anope::string::npos)
            {
                found_safe_salt = true;
                break;
            }
        }
        if (!found_safe_salt)
            return false;

        const auto salted_password = Pbkdf2Sha512(password, out.salt, iterations);
        if (salted_password.length() != SCRAM_SHA512_LEN)
            return false;

        const auto client_key = HmacSha512(salted_password, "Client Key");
        if (client_key.length() != SCRAM_SHA512_LEN)
            return false;
        out.stored_key = Sha512(client_key);
        if (out.stored_key.length() != SCRAM_SHA512_LEN)
            return false;

        out.server_key = HmacSha512(salted_password, "Server Key");
        if (out.server_key.length() != SCRAM_SHA512_LEN)
            return false;

        return true;
    }

    struct ScramVerifier256 final
    {
        unsigned iterations = 0;
        Anope::string salt;       // raw bytes
        Anope::string stored_key; // raw bytes (SHA256)
        Anope::string server_key; // raw bytes (SHA256)
    };

    bool ParseVerifier256(const Anope::string &encoded, ScramVerifier256 &out)
    {
        Anope::map<Anope::string> attrs;
        if (!SplitCommaAttrs(encoded, attrs))
            return false;

        if (!attrs.count("v") || attrs["v"] != "1")
            return false;
        if (!attrs.count("i") || !attrs.count("s") || !attrs.count("sk") || !attrs.count("sv"))
            return false;

        out.iterations = static_cast<unsigned>(Anope::Convert<unsigned>(attrs["i"], 0));
        if (!out.iterations)
            return false;

        out.salt = Anope::B64Decode(attrs["s"]);
        out.stored_key = Anope::B64Decode(attrs["sk"]);
        out.server_key = Anope::B64Decode(attrs["sv"]);

        if (out.salt.empty() || out.stored_key.length() != SCRAM_SHA256_LEN || out.server_key.length() != SCRAM_SHA256_LEN)
            return false;

        return true;
    }

    Anope::string EncodeVerifier256(const ScramVerifier256 &v)
    {
        return "v=1,i=" + Anope::ToString(v.iterations)
            + ",s=" + Anope::B64Encode(v.salt)
            + ",sk=" + Anope::B64Encode(v.stored_key)
            + ",sv=" + Anope::B64Encode(v.server_key);
    }

    bool MakeVerifier256(const Anope::string &password, unsigned iterations, size_t salt_len, ScramVerifier256 &out)
    {
        out = {};
        out.iterations = iterations;
        // Some clients incorrectly mishandle '+' or '/' in the base64 salt.
        // Keep generating until the *standard* base64 encoding avoids those chars.
        bool found_safe_salt = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt)
        {
            out.salt = RandomBytes(salt_len);
            if (out.salt.empty())
                return false;

            const auto salt_b64 = Anope::B64Encode(out.salt);
            if (salt_b64.find('+') == Anope::string::npos && salt_b64.find('/') == Anope::string::npos)
            {
                found_safe_salt = true;
                break;
            }
        }
        if (!found_safe_salt)
            return false;

        const auto salted_password = Pbkdf2Sha256(password, out.salt, iterations);
        if (salted_password.length() != SCRAM_SHA256_LEN)
            return false;

        const auto client_key = HmacSha256(salted_password, "Client Key");
        if (client_key.length() != SCRAM_SHA256_LEN)
            return false;
        out.stored_key = Sha256(client_key);
        if (out.stored_key.length() != SCRAM_SHA256_LEN)
            return false;

        out.server_key = HmacSha256(salted_password, "Server Key");
        if (out.server_key.length() != SCRAM_SHA256_LEN)
            return false;

        return true;
    }

    // Redact SCRAM proofs from debug logs to avoid leaking secrets.
    Anope::string RedactScramProof(const Anope::string &msg)
    {
        // Replace the value of p=... with p=<redacted>
        Anope::string out = msg;
        auto ppos = out.find("p=");
        if (ppos == Anope::string::npos)
            return out;
        auto start = ppos + 2;
        auto end = out.find(',', start);
        if (end == Anope::string::npos)
            end = out.length();
        out = out.substr(0, start) + "<redacted>" + out.substr(end);
        return out;
    }
}

// ── Serializable database for SCRAM verifiers (persisted to m_apiauth.module.json) ──

static constexpr const char *APIAUTH_VERIFIER_DATA_TYPE = "ApiAuthVerifier";

class ApiAuthVerifierEntry;
using apiauth_verifier_map = Anope::unordered_map<ApiAuthVerifierEntry *>;
static Serialize::Checker<apiauth_verifier_map> ApiAuthVerifierList(APIAUTH_VERIFIER_DATA_TYPE);

class ApiAuthVerifierEntry final
    : public Serializable
{
public:
    Anope::string account;
    Anope::string scram_sha512_verifier;
    Anope::string scram_sha256_verifier;

    ApiAuthVerifierEntry(const Anope::string &acct)
        : Serializable(APIAUTH_VERIFIER_DATA_TYPE)
        , account(acct)
    {
        ApiAuthVerifierList->insert_or_assign(acct, this);
    }

    ~ApiAuthVerifierEntry() override
    {
        ApiAuthVerifierList->erase(this->account);
    }

    static ApiAuthVerifierEntry *Find(const Anope::string &acct)
    {
        auto it = ApiAuthVerifierList->find(acct);
        if (it != ApiAuthVerifierList->end())
            return it->second;
        return nullptr;
    }

    static ApiAuthVerifierEntry *FindOrCreate(const Anope::string &acct)
    {
        auto *entry = Find(acct);
        if (!entry)
            entry = new ApiAuthVerifierEntry(acct);
        return entry;
    }
};

class ApiAuthVerifierDataType final
    : public Serialize::Type
{
public:
    ApiAuthVerifierDataType(Module *owner)
        : Serialize::Type(APIAUTH_VERIFIER_DATA_TYPE, owner)
    {
    }

    void Serialize(Serializable *obj, Serialize::Data &data) const override
    {
        const auto *v = static_cast<const ApiAuthVerifierEntry *>(obj);
        data.Store("account", v->account);
        data.Store("scram_sha512_verifier", v->scram_sha512_verifier);
        data.Store("scram_sha256_verifier", v->scram_sha256_verifier);
    }

    Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override
    {
        Anope::string account;
        data.TryLoad("account", account);
        if (account.empty())
            return nullptr;

        ApiAuthVerifierEntry *v = nullptr;
        if (obj)
        {
            v = anope_dynamic_static_cast<ApiAuthVerifierEntry *>(obj);
        }
        else
        {
            v = ApiAuthVerifierEntry::Find(account);
            if (!v)
                v = new ApiAuthVerifierEntry(account);
        }

        v->account = account;
        data.TryLoad("scram_sha512_verifier", v->scram_sha512_verifier);
        data.TryLoad("scram_sha256_verifier", v->scram_sha256_verifier);
        return v;
    }
};

class ApiAuthScramSHA512 final
    : public SASL::Mechanism
{
private:
    struct Session final
        : SASL::Session
    {
        bool saw_client_first = false;
        bool sent_server_final = false;
        Anope::string username;
        Anope::string pending_b64;
        Anope::string client_nonce;
        Anope::string server_nonce;
        Anope::string combined_nonce;
        Anope::string client_first_bare;
        Anope::string gs2_header_b64;
        Anope::string server_first_message;
        Anope::string client_final_wo_proof;
        ScramVerifier verifier;

        Session(SASL::Mechanism *m, const Anope::string &u)
            : SASL::Session(m, u)
        {
        }
    };

    unsigned iterations;
    size_t saltlen;

    bool GetAccountVerifier(NickCore *nc, ScramVerifier &out) const
    {
        if (!nc)
            return false;
        auto *entry = ApiAuthVerifierEntry::Find(nc->display);
        if (!entry || entry->scram_sha512_verifier.empty())
            return false;
        return ParseVerifier(entry->scram_sha512_verifier, out);
    }

    static bool SaltIsClientCompatSafe(const Anope::string &salt_raw)
    {
        const auto salt_b64 = Anope::B64Encode(salt_raw);
        return salt_b64.find('+') == Anope::string::npos && salt_b64.find('/') == Anope::string::npos;
    }

    NickCore *FindUsableAccount(const Anope::string &username)
    {
        if (username.empty() || !IRCD->IsNickValid(username))
            return nullptr;

        NickAlias *na = NickAlias::Find(username);
        if (!na || !na->nc)
            return nullptr;

        NickCore *nc = na->nc;
        if (nc->HasExt("NS_SUSPENDED") || nc->HasExt("UNCONFIRMED"))
            return nullptr;

        return nc;
    }

public:
    ApiAuthScramSHA512(Module *o, unsigned iters, size_t slen)
        : SASL::Mechanism(o, "SCRAM-SHA-512")
        , iterations(iters)
        , saltlen(slen)
    {
        if (iterations < 4096)
            iterations = 4096;
        if (saltlen < 16)
            saltlen = 16;
    }

    Session *CreateSession(const Anope::string &uid) override
    {
        return new Session(this, uid);
    }

    bool HasVerifier(NickCore *nc) const
    {
        ScramVerifier tmp;
        return GetAccountVerifier(nc, tmp);
    }

    bool VerifierHasUnsafeSalt(NickCore *nc) const
    {
        ScramVerifier tmp;
        if (!GetAccountVerifier(nc, tmp))
            return false;
        return !SaltIsClientCompatSafe(tmp.salt);
    }

    bool SetVerifierFromPassword(NickCore *nc, const Anope::string &password)
    {
        if (!nc || password.empty())
            return false;

        ScramVerifier v;
        if (!MakeVerifier(password, iterations, saltlen, v))
            return false;

        auto *entry = ApiAuthVerifierEntry::FindOrCreate(nc->display);
        entry->scram_sha512_verifier = EncodeVerifier(v);
        entry->QueueUpdate();
        return true;
    }

    bool SetVerifierFromEncoded(NickCore *nc, const Anope::string &encoded)
    {
        if (!nc || encoded.empty())
            return false;
        ScramVerifier v;
        if (!ParseVerifier(encoded, v))
            return false;
        auto *entry = ApiAuthVerifierEntry::FindOrCreate(nc->display);
        entry->scram_sha512_verifier = encoded;
        entry->QueueUpdate();
        return true;
    }

    bool ProcessMessage(SASL::Session *sess, const SASL::Message &m) override
    {
        auto *mysess = anope_dynamic_static_cast<Session *>(sess);
        if (!mysess)
            return false;

        const auto &modconf = Config->GetModule(this->owner);
        const bool scram_debug = modconf.Get<bool>("scram_debug", "no");
        const bool scram_attr_b64_nopad = modconf.Get<bool>("scram_attr_b64_nopad", "no");

        if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: message type='" << m.type << "' parts=" << m.data.size() << " from " << sess->GetUserInfo();

        if (m.type == "S")
        {
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: starting handshake";
            SASL::service->SendMessage(sess, "C", "+");
            return true;
        }

        if (m.type != "C")
            return true;

        const auto assembled = AssembleSaslAuthenticateData(m.data, mysess->pending_b64);
        if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: received data chunk (complete=" << (assembled.complete ? "yes" : "no") << ", empty=" << (assembled.empty ? "yes" : "no") << ")";

        if (!assembled.complete)
            return true; // wait for more chunks

        if (mysess->sent_server_final && !assembled.empty)
        {
            const auto b64 = mysess->pending_b64;
            mysess->pending_b64.clear();
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent unexpected data after server-final during SASL SCRAM-SHA-512 for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: protocol error (unexpected client data after server-final) decoded='" << RedactScramProof(Anope::B64Decode(b64)) << "'";
            SASL::service->SendMessage(sess, "C", Anope::B64Encode("e=protocol-error"));
            return false;
        }

        if (assembled.empty)
        {
            mysess->pending_b64.clear();

            if (mysess->sent_server_final)
            {
                NickCore *nc = FindUsableAccount(mysess->username);
                if (!nc)
                    return false;

                if (scram_debug)
                        Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: completed for account '" << nc->display << "'";

                Log(this->owner, "sasl", Config->GetClient("NickServ")) << sess->GetUserInfo() << " identified to account " << nc->display << " using SASL SCRAM-SHA-512";
                SASL::service->Succeed(sess, nc);
                delete sess;
                return true;
            }

            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an empty SASL SCRAM-SHA-512 message (client aborted after server-first; this usually means the client has no SASL password configured or does not support SCRAM)";
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: client aborted (empty message)";

            // SCRAM allows the server to return an error as the final message.
            // This gives clients a hint that the handshake cannot continue.
            SASL::service->SendMessage(sess, "C", Anope::B64Encode("e=other-error"));
            return false;
        }

        const auto b64 = mysess->pending_b64;
        mysess->pending_b64.clear();
        const auto decoded = Anope::B64Decode(b64);
        if (decoded.empty())
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid (non-base64) SASL SCRAM-SHA-512 message";
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: invalid base64 (len=" << b64.length() << ")";
            return false;
        }

        if (scram_debug)
           if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: decoded_len=" << decoded.length();

        if (!mysess->saw_client_first)
        {
            ScramFields fields;
            Anope::string gs2_header;
            if (!ParseClientFirstMessage(decoded, fields, mysess->client_first_bare, gs2_header))
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid SASL SCRAM-SHA-512 client-first message";
                if (scram_debug)
                    Log(LOG_NORMAL, "sasl") << "[api_auth/scram]: invalid client-first from " << sess->GetUserInfo() << " decoded='" << decoded << "'";
                return false;
            }
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: client-first ok (user='" << fields.username << "')";

            mysess->saw_client_first = true;
            mysess->username = fields.username;
            mysess->client_nonce = fields.nonce;
            mysess->gs2_header_b64 = Anope::B64Encode(gs2_header);

            NickCore *nc = FindUsableAccount(mysess->username);
            if (!nc)
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " attempted SASL SCRAM-SHA-512 for nonexistent/suspended/unconfirmed account " << mysess->username;
                if (scram_debug)
                        Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: no usable account (user='" << mysess->username << "')";
                return false;
            }

            if (!GetAccountVerifier(nc, mysess->verifier))
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " attempted SASL SCRAM-SHA-512 for account " << nc->display << " but no SCRAM verifier is stored yet";
                if (scram_debug)
                        Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: missing verifier for account='" << nc->display << "'";
                return false;
            }
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: using verifier (account='" << nc->display << "', i=" << mysess->verifier.iterations << ")";

            if (!SaltIsClientCompatSafe(mysess->verifier.salt))
            {
                // Some clients appear to mishandle '+' and '/' inside base64-encoded salt values.
                // We can't change the encoding in server-first, so the verifier must be regenerated.
                Log(LOG_DEBUG, "sasl") << "[api_auth/scram]: verifier salt base64 contains '+' or '/', some clients may abort; refresh verifier by IDENTIFY/PLAIN";
            }

            mysess->server_nonce = MakeScramServerNonce(18);
            if (mysess->server_nonce.empty())
            {
                Log(LOG_NORMAL, "sasl") << "Failed to generate server nonce for SASL SCRAM-SHA-512";
                return false;
            }

            mysess->combined_nonce = mysess->client_nonce + mysess->server_nonce;
            mysess->server_first_message = "r=" + mysess->combined_nonce
                + ",s=" + ScramAttrB64Encode(mysess->verifier.salt, scram_attr_b64_nopad)
                + ",i=" + Anope::ToString(mysess->verifier.iterations);

            SASL::service->SendMessage(sess, "C", Anope::B64Encode(mysess->server_first_message));
            return true;
        }

        ScramFields fields;
        if (!ParseClientFinalMessage(decoded, fields, mysess->client_final_wo_proof))
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid SASL SCRAM-SHA-512 client-final message for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: invalid client-final decoded='" << RedactScramProof(decoded) << "'";
            return false;
        }
        if (scram_debug)
          if (scram_debug)
             Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: client-final ok (account='" << mysess->username << ")";

        if (fields.channel_binding != mysess->gs2_header_b64)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " used unsupported SCRAM channel binding (c=) during SASL SCRAM-SHA-512 for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: channel binding mismatch";
            return false;
        }

        if (fields.nonce != mysess->combined_nonce)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent a mismatched nonce during SASL SCRAM-SHA-512 for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: nonce mismatch";
            return false;
        }

        const auto client_proof = Anope::B64Decode(fields.proof_b64);
        if (client_proof.length() != SCRAM_SHA512_LEN)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid proof during SASL SCRAM-SHA-512 for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: invalid proof length=" << client_proof.length();
            return false;
        }

        const auto auth_message = mysess->client_first_bare + "," + mysess->server_first_message + "," + mysess->client_final_wo_proof;

        const auto client_signature = HmacSha512(mysess->verifier.stored_key, auth_message);
        if (client_signature.length() != SCRAM_SHA512_LEN)
            return false;

        const auto client_key = XorSameLength(client_proof, client_signature);
        if (client_key.length() != SCRAM_SHA512_LEN)
            return false;

        const auto stored_key_check = Sha512(client_key);
        if (stored_key_check.length() != SCRAM_SHA512_LEN)
            return false;

        if (!ConstantTimeEquals(stored_key_check, mysess->verifier.stored_key))
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " failed SASL SCRAM-SHA-512 authentication for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-512: password check failed (stored_key mismatch)";
            return false;
        }

        const auto server_signature = HmacSha512(mysess->verifier.server_key, auth_message);
        if (server_signature.length() != SCRAM_SHA512_LEN)
            return false;

        SASL::service->SendMessage(sess, "C", Anope::B64Encode("v=" + ScramAttrB64Encode(server_signature, scram_attr_b64_nopad)));
        mysess->sent_server_final = true;
        return true;
    }
};

class ApiAuthScramSHA256 final
    : public SASL::Mechanism
{
private:
    struct Session final
        : SASL::Session
    {
        bool saw_client_first = false;
        bool sent_server_final = false;
        Anope::string username;
        Anope::string pending_b64;
        Anope::string client_nonce;
        Anope::string server_nonce;
        Anope::string combined_nonce;
        Anope::string client_first_bare;
        Anope::string gs2_header_b64;
        Anope::string server_first_message;
        Anope::string client_final_wo_proof;
        ScramVerifier256 verifier;

        Session(SASL::Mechanism *m, const Anope::string &u)
            : SASL::Session(m, u)
        {
        }
    };

    unsigned iterations;
    size_t saltlen;

    bool GetAccountVerifier(NickCore *nc, ScramVerifier256 &out) const
    {
        if (!nc)
            return false;
        auto *entry = ApiAuthVerifierEntry::Find(nc->display);
        if (!entry || entry->scram_sha256_verifier.empty())
            return false;
        return ParseVerifier256(entry->scram_sha256_verifier, out);
    }

    static bool SaltIsClientCompatSafe(const Anope::string &salt_raw)
    {
        const auto salt_b64 = Anope::B64Encode(salt_raw);
        return salt_b64.find('+') == Anope::string::npos && salt_b64.find('/') == Anope::string::npos;
    }

    NickCore *FindUsableAccount(const Anope::string &username)
    {
        if (username.empty() || !IRCD->IsNickValid(username))
            return nullptr;

        NickAlias *na = NickAlias::Find(username);
        if (!na || !na->nc)
            return nullptr;

        NickCore *nc = na->nc;
        if (nc->HasExt("NS_SUSPENDED") || nc->HasExt("UNCONFIRMED"))
            return nullptr;

        return nc;
    }

public:
    ApiAuthScramSHA256(Module *o, unsigned iters, size_t slen)
        : SASL::Mechanism(o, "SCRAM-SHA-256")
        , iterations(iters)
        , saltlen(slen)
    {
        if (iterations < 4096)
            iterations = 4096;
        if (saltlen < 16)
            saltlen = 16;
    }

    Session *CreateSession(const Anope::string &uid) override
    {
        return new Session(this, uid);
    }

    bool HasVerifier(NickCore *nc) const
    {
        ScramVerifier256 tmp;
        return GetAccountVerifier(nc, tmp);
    }

    bool VerifierHasUnsafeSalt(NickCore *nc) const
    {
        ScramVerifier256 tmp;
        if (!GetAccountVerifier(nc, tmp))
            return false;
        return !SaltIsClientCompatSafe(tmp.salt);
    }

    bool SetVerifierFromPassword(NickCore *nc, const Anope::string &password)
    {
        if (!nc || password.empty())
            return false;

        ScramVerifier256 v;
        if (!MakeVerifier256(password, iterations, saltlen, v))
            return false;

        auto *entry = ApiAuthVerifierEntry::FindOrCreate(nc->display);
        entry->scram_sha256_verifier = EncodeVerifier256(v);
        entry->QueueUpdate();
        return true;
    }

    bool SetVerifierFromEncoded(NickCore *nc, const Anope::string &encoded)
    {
        if (!nc || encoded.empty())
            return false;
        ScramVerifier256 v;
        if (!ParseVerifier256(encoded, v))
            return false;
        auto *entry = ApiAuthVerifierEntry::FindOrCreate(nc->display);
        entry->scram_sha256_verifier = encoded;
        entry->QueueUpdate();
        return true;
    }

    bool ProcessMessage(SASL::Session *sess, const SASL::Message &m) override
    {
        auto *mysess = anope_dynamic_static_cast<Session *>(sess);
        if (!mysess)
            return false;

        const auto &modconf = Config->GetModule(this->owner);
        const bool scram_debug = modconf.Get<bool>("scram_debug", "no");
        const bool scram_attr_b64_nopad = modconf.Get<bool>("scram_attr_b64_nopad", "no");

        if (scram_debug)
           if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: message type='" << m.type << "' parts=" << m.data.size() << " from " << sess->GetUserInfo();

        if (m.type == "S")
        {
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: starting handshake";
            SASL::service->SendMessage(sess, "C", "+");
            return true;
        }

        if (m.type != "C")
            return true;

        const auto assembled = AssembleSaslAuthenticateData(m.data, mysess->pending_b64);
        if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: received data chunk (complete=" << (assembled.complete ? "yes" : "no") << ", empty=" << (assembled.empty ? "yes" : "no") << ")";

        if (!assembled.complete)
            return true; // wait for more chunks

        if (mysess->sent_server_final && !assembled.empty)
        {
            mysess->pending_b64.clear();
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent unexpected data after server-final during SASL SCRAM-SHA-256 for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: protocol error (unexpected client data after server-final)";
            SASL::service->SendMessage(sess, "C", Anope::B64Encode("e=protocol-error"));
            return false;
        }

        if (assembled.empty)
        {
            mysess->pending_b64.clear();

            if (mysess->sent_server_final)
            {
                NickCore *nc = FindUsableAccount(mysess->username);
                if (!nc)
                    return false;

                if (scram_debug)
                        Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: completed for account '" << nc->display << "'";

                Log(this->owner, "sasl", Config->GetClient("NickServ")) << sess->GetUserInfo() << " identified to account " << nc->display << " using SASL SCRAM-SHA-256";
                SASL::service->Succeed(sess, nc);
                delete sess;
                return true;
            }

            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an empty SASL SCRAM-SHA-256 message (client aborted after server-first; this usually means the client has no SASL password configured or does not support SCRAM)";
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: client aborted (empty message)";

            SASL::service->SendMessage(sess, "C", Anope::B64Encode("e=other-error"));
            return false;
        }

        const auto b64 = mysess->pending_b64;
        mysess->pending_b64.clear();
        const auto decoded = Anope::B64Decode(b64);
        if (decoded.empty())
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid (non-base64) SASL SCRAM-SHA-256 message";
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: invalid base64 (len=" << b64.length() << ")";
            return false;
        }

        if (scram_debug)
           if (scram_debug)
              Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: decoded_len=" << decoded.length();

        if (!mysess->saw_client_first)
        {
            ScramFields fields;
            Anope::string gs2_header;
            if (!ParseClientFirstMessage(decoded, fields, mysess->client_first_bare, gs2_header))
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid SASL SCRAM-SHA-256 client-first message";
                if (scram_debug)
                    Log(LOG_NORMAL, "sasl") << "[api_auth/scram256]: invalid client-first decoded='" << RedactScramProof(decoded) << "'";
                return false;
            }

            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: client-first ok (user='" << fields.username << "')";

            mysess->saw_client_first = true;
            mysess->username = fields.username;
            mysess->client_nonce = fields.nonce;
            mysess->gs2_header_b64 = Anope::B64Encode(gs2_header);

            NickCore *nc = FindUsableAccount(mysess->username);
            if (!nc)
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " attempted SASL SCRAM-SHA-256 for nonexistent/suspended/unconfirmed account " << mysess->username;
                return false;
            }

            if (!GetAccountVerifier(nc, mysess->verifier))
            {
                Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " attempted SASL SCRAM-SHA-256 for account " << nc->display << " but no SCRAM verifier is stored yet";
                if (scram_debug)
                        Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: missing verifier for account='" << nc->display << "'";
                return false;
            }

            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: using verifier (account='" << nc->display << "', i=" << mysess->verifier.iterations << ")";

            if (!SaltIsClientCompatSafe(mysess->verifier.salt))
            {
                Log(LOG_DEBUG, "sasl") << "[api_auth/scram256]: verifier salt base64 contains '+' or '/', some clients may abort; refresh verifier by IDENTIFY/PLAIN";
            }

            mysess->server_nonce = MakeScramServerNonce(18);
            if (mysess->server_nonce.empty())
            {
                Log(LOG_NORMAL, "sasl") << "Failed to generate server nonce for SASL SCRAM-SHA-256";
                return false;
            }

            mysess->combined_nonce = mysess->client_nonce + mysess->server_nonce;
            mysess->server_first_message = "r=" + mysess->combined_nonce
                + ",s=" + ScramAttrB64Encode(mysess->verifier.salt, scram_attr_b64_nopad)
                + ",i=" + Anope::ToString(mysess->verifier.iterations);

            SASL::service->SendMessage(sess, "C", Anope::B64Encode(mysess->server_first_message));
            return true;
        }

        ScramFields fields;
        if (!ParseClientFinalMessage(decoded, fields, mysess->client_final_wo_proof))
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid SASL SCRAM-SHA-256 client-final message for account " << mysess->username;
            if (scram_debug)
                 Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: invalid client-final decoded='" << RedactScramProof(decoded) << "'";
            return false;
        }

        if (scram_debug)
                if (scram_debug)
                    Log(LOG_DEBUG, "sasl") << "SASL SCRAM-256: client-final ok (account='" << mysess->username << ")";

        if (fields.channel_binding != mysess->gs2_header_b64)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " used unsupported SCRAM channel binding (c=) during SASL SCRAM-SHA-256 for account " << mysess->username;
            return false;
        }

        if (fields.nonce != mysess->combined_nonce)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent a mismatched nonce during SASL SCRAM-SHA-256 for account " << mysess->username;
            return false;
        }

        const auto client_proof = Anope::B64Decode(fields.proof_b64);
        if (client_proof.length() != SCRAM_SHA256_LEN)
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " sent an invalid proof during SASL SCRAM-SHA-256 for account " << mysess->username;
            return false;
        }

        const auto auth_message = mysess->client_first_bare + "," + mysess->server_first_message + "," + mysess->client_final_wo_proof;

        const auto client_signature = HmacSha256(mysess->verifier.stored_key, auth_message);
        if (client_signature.length() != SCRAM_SHA256_LEN)
            return false;

        const auto client_key = XorSameLength(client_proof, client_signature);
        if (client_key.length() != SCRAM_SHA256_LEN)
            return false;

        const auto stored_key_check = Sha256(client_key);
        if (stored_key_check.length() != SCRAM_SHA256_LEN)
            return false;

        if (!ConstantTimeEquals(stored_key_check, mysess->verifier.stored_key))
        {
            Log(LOG_NORMAL, "sasl") << sess->GetUserInfo() << " failed SASL SCRAM-SHA-256 authentication for account " << mysess->username;
            return false;
        }

        const auto server_signature = HmacSha256(mysess->verifier.server_key, auth_message);
        if (server_signature.length() != SCRAM_SHA256_LEN)
            return false;

        SASL::service->SendMessage(sess, "C", Anope::B64Encode("v=" + ScramAttrB64Encode(server_signature, scram_attr_b64_nopad)));
        mysess->sent_server_final = true;
        return true;
    }
};

// Callback for CURL to write response data.
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// Structure to hold API response.
struct APIAuthResponse
{
    bool success;
    Anope::string email;
    Anope::string access_token;  // JWT token returned by the API.
	Anope::string scram_sha512_verifier; // Optional SCRAM verifier string.
	Anope::string scram_sha256_verifier; // Optional SCRAM verifier string.
    Anope::string error_message;
};

class APIAuthRequest
{
private:
    Reference<User> user;
    IdentifyRequest *req;
    Anope::string api_url;
    Anope::string api_username_param;
    Anope::string api_password_param;
    Anope::string api_method;
    Anope::string api_success_field; // Unused in this version.
    Anope::string api_email_field;
    Anope::string api_key;             // API key if needed.
    Anope::string api_verify_ssl;
    Anope::string api_capath;
    Anope::string api_cainfo;

    Anope::string jwt_secret;
    Anope::string jwt_issuer;

	ApiAuthScramSHA512 *scram = nullptr;
    ApiAuthScramSHA256 *scram256 = nullptr;

public:
    // Constructor.
    APIAuthRequest(User *u, IdentifyRequest *r, const Anope::string &url,
                   const Anope::string &username_param, const Anope::string &password_param,
                   const Anope::string &method, const Anope::string &success_field,
                   const Anope::string &email_field, const Anope::string &key,
                   const Anope::string &verify_ssl, const Anope::string &capath, const Anope::string &cainfo,
                                     const Anope::string &jwt_secret_, const Anope::string &jwt_issuer_, ApiAuthScramSHA512 *scram_, ApiAuthScramSHA256 *scram256_)
        : user(u), req(r), api_url(url), api_username_param(username_param),
          api_password_param(password_param), api_method(method),
          api_success_field(success_field), api_email_field(email_field),
          api_key(key), api_verify_ssl(verify_ssl), api_capath(capath), api_cainfo(cainfo),
		  jwt_secret(jwt_secret_), jwt_issuer(jwt_issuer_), scram(scram_), scram256(scram256_)
    {
        req->Hold(me);
    }

    ~APIAuthRequest()
    {
        req->Release(me);
    }

    APIAuthResponse MakeRequest()
    {
        APIAuthResponse response;
        response.success = false;

        CURL *curl = curl_easy_init();
        if (!curl)
        {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: Could not initialize CURL";
            return response;
        }
        
        std::string postData;
        std::string userParam(api_username_param.c_str());
        std::string passParam(api_password_param.c_str());
        std::string url(api_url.c_str());

        const auto &pw = req->GetPassword();
        Log(LOG_COMMAND) << "[api_auth]: Target URL: " << api_url;
        Log(LOG_COMMAND) << "[api_auth]: Account='" << req->GetAccount() << "' password_present="
                 << (!pw.empty() ? "yes" : "no") << " password_length=" << pw.length();
        Log(LOG_COMMAND) << "[api_auth]: API key configured: " << (!api_key.empty() ? "yes" : "no");
        
        char *escaped_user = curl_easy_escape(curl, req->GetAccount().c_str(), 0);
        char *escaped_pass = curl_easy_escape(curl, req->GetPassword().c_str(), 0);

        if (api_method.equals_ci("GET"))
        {
            std::string full_url = url;
            full_url += (full_url.find('?') == std::string::npos) ? "?" : "&";
            full_url += userParam + "=" + (escaped_user ? escaped_user : "");
            full_url += "&" + passParam + "=" + (escaped_pass ? escaped_pass : "");
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
        }
        else
        {
            postData = userParam + "=" + (escaped_user ? escaped_user : "") + "&" +
                       passParam + "=" + (escaped_pass ? escaped_pass : "");
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        }

        if (escaped_user)
            curl_free(escaped_user);
        if (escaped_pass)
            curl_free(escaped_pass);
        
        std::string key(api_key.c_str());
        struct curl_slist *headers = NULL;
        if (!key.empty()) {
            std::string header = "X-API-Key: " + key;
            headers = curl_slist_append(headers, header.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        std::string readBuffer;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Anope-API-Auth/1.0");
        
        bool verify_ssl = (api_verify_ssl == "true" || api_verify_ssl == "1" || api_verify_ssl == "yes");
        if (!verify_ssl)
        {
            Log(LOG_DEBUG) << "[api_auth]: ⚠️ WARNING: SSL verification disabled";
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }
        else if (!api_capath.empty())
        {
            curl_easy_setopt(curl, CURLOPT_CAPATH, api_capath.c_str());
        }
        else if (!api_cainfo.empty())
        {
            curl_easy_setopt(curl, CURLOPT_CAINFO, api_cainfo.c_str());
        }

        Log(LOG_COMMAND) << "[api_auth]: 🔄 Making API request for user @" << req->GetAccount() << "@";
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: CURL failed: " << curl_easy_strerror(res);
            response.error_message = "Connection error: Could not reach authentication server";
            if (headers)
                curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return response;
        }
        
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200)
        {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: API returned HTTP code " << http_code;
            response.error_message = "API error: Unexpected HTTP response code";
            if (headers)
                curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return response;
        }
        
        try {
            json root = json::parse(readBuffer);
            // Check for the presence of the access_token field.
            if (root.contains("access_token"))
            {
                response.success = true;
                response.access_token = root["access_token"].get<std::string>().c_str();
                if (!api_email_field.empty() && root.contains(std::string(api_email_field.c_str()))) {
                    std::string email_field = std::string(api_email_field.c_str());
                    response.email = root[email_field].get<std::string>().c_str();
                }
				if (root.contains("scram_sha512_verifier") && root["scram_sha512_verifier"].is_string())
					response.scram_sha512_verifier = root["scram_sha512_verifier"].get<std::string>().c_str();
                if (root.contains("scram_sha256_verifier") && root["scram_sha256_verifier"].is_string())
                    response.scram_sha256_verifier = root["scram_sha256_verifier"].get<std::string>().c_str();
            }
            else {
                if (root.contains("error") && root["error"].is_string())
                    response.error_message = root["error"].get<std::string>().c_str();
                else if (root.contains("detail") && root["detail"].is_string())
                    response.error_message = root["detail"].get<std::string>().c_str();
                else
                    response.error_message = "API response missing access_token field";
            }
        }
        catch (const json::parse_error &e) {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: JSON parse error: " << e.what();
            Log(LOG_COMMAND) << "[api_auth]: Response was: " << readBuffer;
            response.error_message = "JSON parse error";
        }
        catch (const std::exception &e) {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: JSON exception: " << e.what();
            response.error_message = "JSON exception";
        }
        
        if (headers)
            curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return response;
    }

    void ProcessAuth()
    {
        APIAuthResponse response = MakeRequest();
        if (response.success) {
            Log(LOG_COMMAND) << "[api_auth]: ✅ SUCCESS: User @" << req->GetAccount() << "@ authenticated!";
            // Decode the JWT token to determine the canonical username.
            Anope::string effective_account = req->GetAccount();
            if (!response.access_token.empty()) {
                try {
                    std::string token_str(response.access_token.c_str());
                    auto decoded = jwt::decode(token_str);

                    if (!this->jwt_secret.empty() && !this->jwt_issuer.empty())
                    {
                        std::string jwt_secret_str(this->jwt_secret.c_str());
                        std::string expected_issuer(this->jwt_issuer.c_str());
                        jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{jwt_secret_str})
                            .with_issuer(expected_issuer)
                            .verify(decoded);
                    }
                    else
                    {
                        Log(LOG_DEBUG) << "[api_auth]: JWT verification disabled (jwt_secret/jwt_issuer not configured)";
                    }

                    std::string subject = decoded.get_payload_claim("sub").as_string();
                    if (!subject.empty())
                        effective_account = subject.c_str();
                } catch (const std::exception &ex) {
                    Log(me, "api_auth") << "JWT decoding/verification failed: " << ex.what();
                    // Fall back to req->GetAccount() if verification fails.
                }
            }
            
            Log(LOG_COMMAND) << "[api_auth]: Using effective account: " << effective_account;
            
            NickAlias *na = NickAlias::Find(effective_account);
            BotInfo *NickServ = Config->GetClient("NickServ");
            if (na == NULL) {
                na = new NickAlias(effective_account, new NickCore(effective_account));
                FOREACH_MOD(OnNickRegister, (user, na, ""));
                if (user && NickServ)
                    user->SendMessage(NickServ, _("Your account \002%s\002 has been confirmed."), na->nick.c_str());
            }

            // Opportunistically store SCRAM verifiers so SASL SCRAM can work
            // for this account on subsequent connections.
            if (na && na->nc)
            {
                bool stored512 = false;
                if (this->scram)
                {
                    const bool needs_refresh = !this->scram->HasVerifier(na->nc) || this->scram->VerifierHasUnsafeSalt(na->nc);
                    if (needs_refresh)
                    {
                        // Prefer the API-provided verifier if present; otherwise derive from password.
                        if (!response.scram_sha512_verifier.empty())
                            stored512 = this->scram->SetVerifierFromEncoded(na->nc, response.scram_sha512_verifier);
                        // If the API verifier is missing or client-incompatible, derive locally (generates a "safe" salt).
                        if (!stored512 || this->scram->VerifierHasUnsafeSalt(na->nc))
                            stored512 = this->scram->SetVerifierFromPassword(na->nc, req->GetPassword());
                    }
                }
                else
                {
                    // If another module provides the mechanism, try to use its shared verifier service.
                    ServiceReference<SASLScram::VerifierService> svc("SASLScram::VerifierService", "SCRAM-SHA-512");
                    if (svc && !svc->HasVerifier(na->nc))
                    {
                        svc->SetVerifierFromPassword(na->nc, req->GetPassword());
                        stored512 = svc->HasVerifier(na->nc);
                    }
                }

                if (stored512)
                    Log(LOG_COMMAND) << "[api_auth]: Stored SCRAM-SHA-512 verifier for " << na->nc->display;

                bool stored256 = false;
                if (this->scram256)
                {
                    const bool needs_refresh = !this->scram256->HasVerifier(na->nc) || this->scram256->VerifierHasUnsafeSalt(na->nc);
                    if (needs_refresh)
                    {
                        if (!response.scram_sha256_verifier.empty())
                            stored256 = this->scram256->SetVerifierFromEncoded(na->nc, response.scram_sha256_verifier);
                        if (!stored256 || this->scram256->VerifierHasUnsafeSalt(na->nc))
                            stored256 = this->scram256->SetVerifierFromPassword(na->nc, req->GetPassword());
                    }
                }
                else
                {
                    ServiceReference<SASLScram::VerifierService> svc("SASLScram::VerifierService", "SCRAM-SHA-256");
                    if (svc && !svc->HasVerifier(na->nc))
                    {
                        svc->SetVerifierFromPassword(na->nc, req->GetPassword());
                        stored256 = svc->HasVerifier(na->nc);
                    }
                }

                if (stored256)
                    Log(LOG_COMMAND) << "[api_auth]: Stored SCRAM-SHA-256 verifier for " << na->nc->display;
            }

            if (!response.email.empty() && response.email != na->nc->email) {
                na->nc->email = response.email;
                if (user && NickServ)
                    user->SendMessage(NickServ, _("E-mail set to \002%s\002."), response.email.c_str());
            }
            // Optionally, store the JWT token (response.access_token) for further usage.
            req->Success(me, na);
        } else {
            Log(LOG_COMMAND) << "[api_auth]: ❌ ERROR: Authentication failed for user " 
                             << req->GetAccount() << " - " 
                             << (!response.error_message.empty() ? response.error_message : "Invalid credentials");
            // Do not call Success(); IdentifyRequest will invoke OnFail() when released.
        }
        delete this;
    }
};

class ModuleAPIAuth final : public Module {
    Anope::string api_url;
    Anope::string api_username_param;
    Anope::string api_password_param;
    Anope::string api_method;
    // api_success_field is not used in this version.
    Anope::string api_email_field;
    Anope::string disable_reason;
    Anope::string disable_email_reason;
    Anope::string api_key;
    Anope::string api_verify_ssl;
    Anope::string api_capath;
    Anope::string api_cainfo;
    Anope::string jwt_secret;
    Anope::string jwt_issuer;
    Anope::string profile_url;
    Anope::string register_url;

    bool enable_sasl_scram_sha512 = false;
    bool enable_sasl_scram_sha256 = true;
    unsigned scram_iterations = 4096;
    size_t scram_saltlen = 16;

    void BroadcastSaslMechsIfSynced()
    {
        if (Me && Me->IsSynced() && SASL::protocol_interface)
        {
            auto mechs = ::Service::GetServiceKeys("SASL::Mechanism");

            // Prioritize SCRAM-SHA-256 first, then other SCRAM variants,
            // with PLAIN as the last fallback.
            std::sort(mechs.begin(), mechs.end(), [](const Anope::string &a, const Anope::string &b) {
                auto priority = [](const Anope::string &m) -> int {
                    if (m == "SCRAM-SHA-256") return 0;
                    if (m.find("SCRAM-") == 0) return 1;
                    if (m == "PLAIN") return 3;
                    return 2;
                };
                return priority(a) < priority(b);
            });

            SASL::protocol_interface->SendSASLMechanisms(mechs);
        }
    }

    class ScramVerifierServiceImpl final
        : public SASLScram::VerifierService
    {
        ApiAuthScramSHA512 &scram;

    public:
        ScramVerifierServiceImpl(Module *creator, ApiAuthScramSHA512 &s)
            : SASLScram::VerifierService(creator, "SCRAM-SHA-512")
            , scram(s)
        {
        }

        bool HasVerifier(NickCore *nc) const override
        {
            return scram.HasVerifier(nc);
        }

        void SetVerifierFromPassword(NickCore *nc, const Anope::string &password) override
        {
            scram.SetVerifierFromPassword(nc, password);
        }
    };

    std::unique_ptr<ApiAuthScramSHA512> scram_mech;
    std::unique_ptr<ScramVerifierServiceImpl> scram_service;

    class Scram256VerifierServiceImpl final
        : public SASLScram::VerifierService
    {
        ApiAuthScramSHA256 &scram;

    public:
        Scram256VerifierServiceImpl(Module *creator, ApiAuthScramSHA256 &s)
            : SASLScram::VerifierService(creator, "SCRAM-SHA-256")
            , scram(s)
        {
        }

        bool HasVerifier(NickCore *nc) const override
        {
            return scram.HasVerifier(nc);
        }

        void SetVerifierFromPassword(NickCore *nc, const Anope::string &password) override
        {
            scram.SetVerifierFromPassword(nc, password);
        }
    };

    std::unique_ptr<ApiAuthScramSHA256> scram256_mech;
    std::unique_ptr<Scram256VerifierServiceImpl> scram256_service;

    ApiAuthVerifierDataType verifier_type;
public:
    ModuleAPIAuth(const Anope::string &modname, const Anope::string &creator)
        : Module(modname, creator, EXTRA | VENDOR)
        , verifier_type(this)
    {
        me = this;
        curl_global_init(CURL_GLOBAL_ALL);
    }
    ~ModuleAPIAuth() {
        curl_global_cleanup();
    }
    void OnReload(Configuration::Conf &conf) override {
        Configuration::Block &config = conf.GetModule(this);
        this->api_url = config.Get<const Anope::string>("api_url", "https://www.example/accounts/api/login_token/");
        this->api_username_param = config.Get<const Anope::string>("api_username_param", "username");
        this->api_password_param = config.Get<const Anope::string>("api_password_param", "password");
        this->api_method = config.Get<const Anope::string>("api_method", "POST");
        this->api_email_field = config.Get<const Anope::string>("api_email_field", "email");
        this->disable_reason = config.Get<const Anope::string>("disable_reason");
        this->disable_email_reason = config.Get<const Anope::string>("disable_email_reason");
        this->api_key = config.Get<const Anope::string>("api_key", "");
        this->api_verify_ssl = config.Get<const Anope::string>("verify_ssl", "true");
        this->api_capath = config.Get<const Anope::string>("capath", "");
        this->api_cainfo = config.Get<const Anope::string>("cainfo", "");
        this->jwt_secret = config.Get<const Anope::string>("jwt_secret", "");
        this->jwt_issuer = config.Get<const Anope::string>("jwt_issuer", "");
        this->profile_url = config.Get<const Anope::string>("profile_url", "https://www.example/accounts/profile/%s/"); // dynamic fetch
        this->register_url = config.Get<const Anope::string>("register_url", "https://www.example/accounts/register/");

        this->enable_sasl_scram_sha512 = config.Get<bool>("enable_sasl_scram_sha512", "no");
        this->enable_sasl_scram_sha256 = config.Get<bool>("enable_sasl_scram_sha256", "yes");
        // Allow both the explicit scram_* names and the historical iterations/saltlen
        // keys (used by ns_sasl_scram_sha512) to reduce config friction.
        this->scram_iterations = config.Get<unsigned>("scram_iterations", config.Get<Anope::string>("iterations", "4096"));
        this->scram_saltlen = config.Get<size_t>("scram_saltlen", config.Get<Anope::string>("saltlen", "16"));
        if (this->scram_iterations < 4096)
            this->scram_iterations = 4096;
        if (this->scram_saltlen < 16)
            this->scram_saltlen = 16;

        if (this->enable_sasl_scram_sha512)
        {
            if (!SASL::protocol_interface)
            {
                Log(LOG_DEBUG) << "[api_auth]: SASL SCRAM-SHA-512 enabled but IRCd does not support SASL";
            }
            else if (!this->scram_mech)
            {
                if (Service::FindService("SASL::Mechanism", "SCRAM-SHA-512"))
                {
                    Log(LOG_DEBUG) << "[api_auth]: SASL::Mechanism SCRAM-SHA-512 already registered by another module; skipping";
                }
                else
                {
                    this->scram_mech = std::make_unique<ApiAuthScramSHA512>(this, this->scram_iterations, this->scram_saltlen);
                    if (!Service::FindService("SASLScram::VerifierService", "SCRAM-SHA-512"))
                        this->scram_service = std::make_unique<ScramVerifierServiceImpl>(this, *this->scram_mech);
                    Log(LOG_COMMAND) << "[api_auth]: SASL SCRAM-SHA-512 mechanism registered";
                    BroadcastSaslMechsIfSynced();
                }
            }
        }
        else if (this->scram_mech)
        {
            // SCRAM was disabled; unregister the mechanism services.
            this->scram_service.reset();
            this->scram_mech.reset();
            BroadcastSaslMechsIfSynced();
        }

        if (this->enable_sasl_scram_sha256)
        {
            if (!SASL::protocol_interface)
            {
                Log(LOG_DEBUG) << "[api_auth]: SASL SCRAM-SHA-256 enabled but IRCd does not support SASL";
            }
            else if (!this->scram256_mech)
            {
                if (Service::FindService("SASL::Mechanism", "SCRAM-SHA-256"))
                {
                    Log(LOG_DEBUG) << "[api_auth]: SASL::Mechanism SCRAM-SHA-256 already registered by another module; skipping";
                }
                else
                {
                    this->scram256_mech = std::make_unique<ApiAuthScramSHA256>(this, this->scram_iterations, this->scram_saltlen);
                    if (!Service::FindService("SASLScram::VerifierService", "SCRAM-SHA-256"))
                        this->scram256_service = std::make_unique<Scram256VerifierServiceImpl>(this, *this->scram256_mech);
                    Log(LOG_COMMAND) << "[api_auth]: SASL SCRAM-SHA-256 mechanism registered";
                    BroadcastSaslMechsIfSynced();
                }
            }
        }
        else if (this->scram256_mech)
        {
            this->scram256_service.reset();
            this->scram256_mech.reset();
            BroadcastSaslMechsIfSynced();
        }
    }

    void OnPreUplinkSync(Server *) override
    {
        // Ensure SCRAM mechs are included in the mechlist at initial sync.
        if ((this->scram_mech || this->scram256_mech) && SASL::protocol_interface)
            BroadcastSaslMechsIfSynced();
    }
    EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override {
        if (!this->disable_reason.empty() && (command->name == "nickserv/register" || command->name == "nickserv/group")) {
            Anope::string formatted_reason = this->disable_reason;
            if (formatted_reason.find("%s") != Anope::string::npos)
                formatted_reason = formatted_reason.replace_all_cs("%s", this->register_url);
            else if (!this->register_url.empty())
                formatted_reason += " " + this->register_url;
            source.Reply(formatted_reason);
            return EVENT_STOP;
        }
        if (!this->disable_email_reason.empty() && command->name == "nickserv/set/email") {
            Anope::string account = source.GetAccount() ? source.GetAccount()->display : "";
            Anope::string formatted_url = this->profile_url;
            if (account.empty())
                account = "";
            if (formatted_url.find("%s") != Anope::string::npos)
                formatted_url = formatted_url.replace_all_cs("%s", account);
            Anope::string formatted_reason = this->disable_email_reason;
            if (formatted_reason.find("%s") != Anope::string::npos)
                formatted_reason = formatted_reason.replace_all_cs("%s", formatted_url);
            else
                formatted_reason += " " + formatted_url;
            source.Reply(formatted_reason);
            return EVENT_STOP;
        }
        return EVENT_CONTINUE;
    }
    void OnCheckAuthentication(User *u, IdentifyRequest *req) override {
        Log(LOG_COMMAND) << "[api_auth]: 🔎 Checking authentication for " << req->GetAccount();
        APIAuthRequest *auth_req = new APIAuthRequest(u, req, this->api_url,
                                                      this->api_username_param,
                                                      this->api_password_param,
                                                      this->api_method,
                                                      "", // success field not used
                                                      this->api_email_field,
                                                      this->api_key,
                                                      this->api_verify_ssl,
                                                      this->api_capath,
                                                      this->api_cainfo,
                                                      this->jwt_secret,
                                                      this->jwt_issuer,
                                                          this->scram_mech.get(), this->scram256_mech.get());
        auth_req->ProcessAuth();
    }
    void OnPreNickExpire(NickAlias *na, bool &expire) override {
        if (na->nick == na->nc->display && na->nc->aliases->size() > 1)
            expire = false;
    }
};

MODULE_INIT(ModuleAPIAuth)