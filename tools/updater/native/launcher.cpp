// Native Windows launcher for the signed updater protocol in updater/core.py.
// Copyright (c) 2026 ZDECHLAK. Distributed under the project MIT license.
#include <nlohmann/json.hpp>
#include <monocypher-ed25519.h>
#include "trust.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <set>
#include <regex>
#include <ctime>
#include <functional>
#include <algorithm>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shellapi.h>
#else
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using J = nlohmann::json;
using Bytes = std::vector<unsigned char>;
constexpr size_t MAX_MANIFEST = 2 * 1024 * 1024, MAX_FILE = 128 * 1024 * 1024;
constexpr uint64_t MAX_TOTAL = 1024ull * 1024 * 1024;
static std::function<void(const std::string&)> progress = [](const std::string& s){ std::cout << s << std::endl; };
static std::string expected_channel = "prototype";
static void need(bool ok, const std::string& error) { if (!ok) throw std::runtime_error(error); }
static std::string lower(std::string s) { for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32; return s; }
static bool match(const std::string& s, const char* pattern) { return std::regex_match(s, std::regex(pattern)); }
static std::string hex(const unsigned char* p, size_t n) {
    std::string r; for (size_t i=0;i<n;++i) { r += "0123456789abcdef"[p[i]>>4]; r += "0123456789abcdef"[p[i]&15]; } return r;
}
static Bytes bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
static std::string sha(const Bytes& data) {
    unsigned char hash[32];
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE handle = nullptr;
    need(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "SHA256 provider failed");
    NTSTATUS status = BCryptCreateHash(alg, &handle, nullptr, 0, nullptr, 0, 0);
    if (!status) status = BCryptHashData(handle, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
    if (!status) status = BCryptFinishHash(handle, hash, sizeof(hash), 0);
    if (handle) BCryptDestroyHash(handle); BCryptCloseAlgorithmProvider(alg, 0);
    need(status == 0, "SHA256 failed");
#else
    SHA256(data.data(), data.size(), hash);
#endif
    return hex(hash, sizeof(hash));
}
static std::string random_id() {
    unsigned char data[16];
#ifdef _WIN32
    need(BCryptGenRandom(nullptr, data, sizeof(data), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "Random generator failed");
#else
    std::ifstream in("/dev/urandom", std::ios::binary); in.read(reinterpret_cast<char*>(data), sizeof(data)); need(bool(in), "Random generator failed");
#endif
    return hex(data, sizeof(data));
}
static void no_links(const fs::path& input) {
    fs::path part;
    for (const auto& component : fs::absolute(input)) {
        part /= component;
#ifdef _WIN32
        DWORD attrs = GetFileAttributesW(part.c_str());
        need(attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_REPARSE_POINT), "Reparse point forbidden: " + part.u8string());
#else
        need(!fs::is_symlink(fs::symlink_status(part)), "Symlink forbidden: " + part.string());
#endif
    }
}
static Bytes read(const fs::path& p, uint64_t limit=MAX_FILE) {
    no_links(p); need(fs::is_regular_file(p), "Missing regular file: " + p.u8string());
    auto n = fs::file_size(p); need(n <= limit, "File exceeds limit: " + p.u8string());
    Bytes out(static_cast<size_t>(n)); std::ifstream in(p, std::ios::binary);
    in.read(reinterpret_cast<char*>(out.data()), out.size()); need(bool(in), "Cannot read: " + p.u8string()); return out;
}
static J parse(const Bytes& b) {
    std::vector<std::set<std::string>> keys;
    auto callback = [&](int, J::parse_event_t event, J& value) {
        if (event == J::parse_event_t::object_start) keys.emplace_back();
        if (event == J::parse_event_t::key) need(keys.back().insert(value.get<std::string>()).second, "Duplicate JSON key");
        if (event == J::parse_event_t::object_end) keys.pop_back();
        need(keys.size() <= 64, "JSON nesting too deep"); return true;
    };
    return J::parse(b.begin(), b.end(), callback);
}
static J read_json(const fs::path& p) { return parse(read(p, MAX_MANIFEST)); }
static void exact(const J& j, std::initializer_list<const char*> fields) {
    need(j.is_object() && j.size() == fields.size(), "Invalid JSON schema");
    for (auto f:fields) need(j.contains(f), std::string("Missing field: ")+f);
}
static uint64_t integer(const J& v, uint64_t minimum=0, uint64_t maximum=INT64_MAX) {
    need(v.is_number_integer() && !v.is_boolean(), "Expected integer");
    if (v.is_number_unsigned()) { auto n=v.get<uint64_t>(); need(n>=minimum && n<=maximum,"Integer out of range"); return n; }
    auto n=v.get<int64_t>(); need(n>=0 && static_cast<uint64_t>(n)>=minimum && static_cast<uint64_t>(n)<=maximum,"Integer out of range"); return n;
}
static Bytes base64(const J& value) {
    need(value.is_string(), "Expected base64 string"); std::string s=value.get<std::string>();
    need(s.size()%4==0,"Invalid base64 length"); Bytes out;
    const std::string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(size_t i=0;i<s.size();i+=4) {
        unsigned v[4];
        for(int k=0;k<4;++k) { auto pos=alphabet.find(s[i+k]); need(pos!=std::string::npos || (s[i+k]=='=' && k>=2 && i+4==s.size()),"Invalid base64"); v[k]=pos==std::string::npos?0:static_cast<unsigned>(pos); }
        need(s[i+2]!='=' || s[i+3]=='=',"Invalid base64 padding");
        out.push_back((v[0]<<2)|(v[1]>>4));
        if(s[i+2]!='=') out.push_back((v[1]<<4)|(v[2]>>2));
        if(s[i+3]!='=') out.push_back((v[2]<<6)|v[3]);
    } return out;
}
static std::string validate_path(const J& value) {
    need(value.is_string(),"Invalid path type"); auto name=value.get<std::string>();
    need(name.size()>=1 && name.size()<=220 && match(name,"[A-Za-z0-9_./-]+"),"Forbidden path: "+name);
    std::vector<std::string> parts; size_t start=0;
    do { auto end=name.find('/',start); auto part=name.substr(start,end-start);
        need(!part.empty() && part!="." && part!=".." && part.back()!='.' && part.size()<=100,"Unsafe path: "+name);
        auto stem=lower(part.substr(0,part.find('.')));
        need(!match(stem,"con|prn|aux|nul|clock\\$|com[0-9]|lpt[0-9]"),"Reserved Windows path");
        parts.push_back(part); if(end==std::string::npos) break; start=end+1;
    } while(true);
    bool root=name=="init.lua" || name=="otclientrc.lua" || name=="build-info.json" || name=="ZDECHLAK-client.exe" || name=="update-marker.txt";
    bool dll=parts.size()==1 && match(lower(name),".*\\.dll");
    bool dir=parts.size()>1 && (parts[0]=="data" || parts[0]=="modules" || parts[0]=="mods" || parts[0]=="licenses" || parts[0]=="layouts");
    need(root || dll || dir,"Path outside update allowlist: "+name); return name;
}
struct Manifest { J doc; std::string digest; };
static Manifest verify_manifest(const Bytes& envelope, bool check_time) {
    need(envelope.size()<=MAX_MANIFEST,"Manifest too large"); auto outer=parse(envelope);
    exact(outer,{"algorithm","payload","signature"}); need(outer["algorithm"]=="Ed25519","Unsupported signature algorithm");
    auto payload=base64(outer["payload"]), signature=base64(outer["signature"]);
    need(signature.size()==64 && crypto_ed25519_check(signature.data(), public_key, payload.data(), payload.size())==0,"Invalid Ed25519 signature");
    auto d=parse(payload); exact(d,{"schema","app","platform","channel","version","sequence","issued_at","expires_at","files"});
    need(integer(d["schema"])==1 && d["app"]=="ZDECHLAK" && d["platform"]=="windows-x64" && d["channel"]==expected_channel,"Manifest target mismatch");
    integer(d["sequence"],1); auto issued=integer(d["issued_at"],1), expires=integer(d["expires_at"],1);
    need(d["version"].is_string() && match(d["version"].get<std::string>(),"[0-9]+\\.[0-9]+\\.[0-9]+(-[a-z0-9.-]+)?"),"Invalid version");
    need(expires>issued && expires-issued<=31*86400,"Invalid validity interval");
    auto now=static_cast<uint64_t>(std::time(nullptr));
    need(!check_time || (issued<=now+300 && expires>now),"Expired or future manifest");
    need(d["files"].is_array() && d["files"].size()>=1 && d["files"].size()<=5000,"Invalid file count");
    uint64_t total=0; std::set<std::string> names;
    for(const auto& e:d["files"]) {
        exact(e,{"path","size","sha256"}); auto name=lower(validate_path(e["path"]));
        need(names.insert(name).second,"Duplicate or case-colliding file"); total+=integer(e["size"],0,MAX_FILE);
        need(e["sha256"].is_string() && match(e["sha256"].get<std::string>(),"[a-f0-9]{64}"),"Invalid SHA256");
    }
    need(total<=MAX_TOTAL,"Release exceeds size limit");
    for(const auto& name:names) for(auto pos=name.find('/');pos!=std::string::npos;pos=name.find('/',pos+1))
        need(!names.count(name.substr(0,pos)),"File/directory collision");
    return {d,sha(payload)};
}
static Manifest verify_launcher_manifest(const Bytes& envelope, bool check_time) {
    need(envelope.size()<=MAX_MANIFEST,"Manifest too large"); auto outer=parse(envelope);
    exact(outer,{"algorithm","payload","signature"}); need(outer["algorithm"]=="Ed25519","Unsupported signature algorithm");
    auto payload=base64(outer["payload"]), signature=base64(outer["signature"]);
    need(signature.size()==64 && crypto_ed25519_check(signature.data(), public_key, payload.data(), payload.size())==0,"Invalid Ed25519 signature");
    auto d=parse(payload); exact(d,{"schema","app","platform","channel","kind","version","sequence","issued_at","expires_at","file"});
    need(integer(d["schema"])==1 && d["app"]=="ZDECHLAK" && d["platform"]=="windows-x64" && d["channel"]==expected_channel && d["kind"]=="launcher","Launcher manifest target mismatch");
    integer(d["sequence"],1); auto issued=integer(d["issued_at"],1), expires=integer(d["expires_at"],1);
    need(d["version"].is_string() && match(d["version"].get<std::string>(),"[0-9]+\\.[0-9]+\\.[0-9]+(-[a-z0-9.-]+)?"),"Invalid version");
    need(expires>issued && expires-issued<=31*86400,"Invalid validity interval");
    auto now=static_cast<uint64_t>(std::time(nullptr));
    need(!check_time || (issued<=now+300 && expires>now),"Expired or future launcher manifest");
    exact(d["file"],{"name","size","sha256"});
    need(d["file"]["name"]=="ZDECHLAK-Launcher.exe","Invalid launcher payload name");
    integer(d["file"]["size"],1,MAX_FILE);
    need(d["file"]["sha256"].is_string() && match(d["file"]["sha256"].get<std::string>(),"[a-f0-9]{64}"),"Invalid launcher SHA256");
    return {d,sha(payload)};
}
static void write_file(const fs::path& p, const Bytes& data) {
    no_links(p);
#ifdef _WIN32
    HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    need(h!=INVALID_HANDLE_VALUE,"Cannot create: "+p.u8string()); DWORD written=0;
    bool ok=WriteFile(h,data.data(),static_cast<DWORD>(data.size()),&written,nullptr) && written==data.size() && FlushFileBuffers(h);
    CloseHandle(h); need(ok,"Cannot flush: "+p.u8string());
#else
    int fd=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600); need(fd>=0,"Cannot create file");
    size_t done=0; bool ok=true;
    while(done<data.size()) { auto n=::write(fd,data.data()+done,data.size()-done); if(n<=0) {ok=false;break;} done+=n; }
    ok=fsync(fd)==0 && ok; close(fd); need(ok,"Cannot flush file");
#endif
}
static void replace_file(const fs::path& target, const Bytes& data) {
    no_links(target);
    auto temp = target.parent_path() / (".new-" + random_id());
    try {
        write_file(temp, data);
#ifdef _WIN32
        need(MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH), "Cannot replace: " + target.u8string());
#else
        fs::rename(temp, target);
#endif
    } catch (...) { fs::remove(temp); throw; }
}
static void atomic_json(const fs::path& p, const J& value) {
    no_links(p); auto temp=p.parent_path()/(".tmp-"+random_id());
    try { write_file(temp,bytes(value.dump()));
#ifdef _WIN32
        need(MoveFileExW(temp.c_str(),p.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH),"Atomic state replacement failed");
#else
        fs::rename(temp,p); int fd=open(p.parent_path().c_str(),O_RDONLY|O_DIRECTORY); if(fd>=0) {fsync(fd);close(fd);}
#endif
    } catch(...) { fs::remove(temp); throw; }
}
struct Lock {
#ifdef _WIN32
    HANDLE h=INVALID_HANDLE_VALUE;
    explicit Lock(const fs::path& p) {no_links(p); h=CreateFileW(p.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);need(h!=INVALID_HANDLE_VALUE,"ZDECHLAK jest juz uruchomiony albo katalog jest niedostepny");}
    ~Lock(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
#else
    int fd=-1;
    explicit Lock(const fs::path& p) {no_links(p);fd=open(p.c_str(),O_RDWR|O_CREAT|O_NOFOLLOW,0600);if(fd<0 || flock(fd,LOCK_EX|LOCK_NB)!=0){if(fd>=0)close(fd);throw std::runtime_error("ZDECHLAK is already running");}}
    ~Lock(){if(fd>=0)close(fd);}
#endif
    Lock(const Lock&)=delete; Lock& operator=(const Lock&)=delete;
};
#ifdef _WIN32
static std::wstring wide(const std::string& s) {int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),s.size(),nullptr,0);need(n>0 || s.empty(),"Invalid UTF8");std::wstring w(n,0);if(n)MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),s.size(),&w[0],n);return w;}
static std::string utf8(const std::wstring& w) {int n=WideCharToMultiByte(CP_UTF8,0,w.data(),w.size(),nullptr,0,nullptr,nullptr);std::string s(n,0);if(n)WideCharToMultiByte(CP_UTF8,0,w.data(),w.size(),&s[0],n,nullptr,nullptr);return s;}
struct Internet { HINTERNET h; explicit Internet(HINTERNET value):h(value){need(h!=nullptr,"HTTPS connection failed");} ~Internet(){WinHttpCloseHandle(h);} operator HINTERNET() const{return h;} };
#endif
static std::string endpoint(std::string url) {
    need(match(url,"https://[A-Za-z0-9.:[\\]_-]+(/[A-Za-z0-9_/-]*)?"),"Endpoint requires HTTPS and plain base path");
    while(!url.empty() && url.back()=='/')url.pop_back();return url;
}
#ifdef ZDECHLAK_NATIVE_TEST
static fs::path test_objects;
#endif
static Bytes fetch(const std::string& url, uint64_t limit) {
#ifdef _WIN32
    auto w=wide(url); URL_COMPONENTS c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=static_cast<DWORD>(-1);c.dwUrlPathLength=static_cast<DWORD>(-1);c.dwExtraInfoLength=static_cast<DWORD>(-1);
    need(WinHttpCrackUrl(w.c_str(),w.size(),0,&c) && c.nScheme==INTERNET_SCHEME_HTTPS && c.dwExtraInfoLength==0,"Invalid HTTPS URL");
    Internet session(WinHttpOpen(L"ZDECHLAK/1.0",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0));
    DWORD tls=WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2; need(WinHttpSetOption(session,WINHTTP_OPTION_SECURE_PROTOCOLS,&tls,sizeof(tls)),"Cannot enforce TLS 1.2");
    need(WinHttpSetTimeouts(session,15000,15000,15000,15000),"Cannot set HTTPS timeout");
    std::wstring host(c.lpszHostName,c.dwHostNameLength),path(c.lpszUrlPath,c.dwUrlPathLength);
    Internet connection(WinHttpConnect(session,host.c_str(),c.nPort,0));
    Internet request(WinHttpOpenRequest(connection,L"GET",path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE));
    DWORD disabled=WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_COOKIES;
    need(WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled)),"Cannot disable redirects");
    need(WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) && WinHttpReceiveResponse(request,nullptr),"HTTPS download failed (certificate, network or server)");
    DWORD status=0,size=sizeof(status);need(WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX) && status==200,"Unexpected HTTP status; redirects forbidden");
    bool has_length=false; uint64_t length=0;wchar_t length_text[64];size=sizeof(length_text);
    if(WinHttpQueryHeaders(request,WINHTTP_QUERY_CONTENT_LENGTH,WINHTTP_HEADER_NAME_BY_INDEX,length_text,&size,WINHTTP_NO_HEADER_INDEX)) {
        auto s=utf8(length_text);need(match(s,"[0-9]+"),"Invalid Content-Length");length=std::stoull(s);need(length<=limit,"Response exceeds size limit");has_length=true;
    } else need(GetLastError()==ERROR_WINHTTP_HEADER_NOT_FOUND,"Invalid Content-Length header");
    Bytes data; unsigned char buffer[65536];
    while(true) {DWORD n=0;need(WinHttpReadData(request,buffer,sizeof(buffer),&n),"Truncated HTTPS response");if(!n)break;need(data.size()+n<=limit,"Response exceeds size limit");data.insert(data.end(),buffer,buffer+n);}
    need(!has_length || data.size()==length,"Truncated Content-Length");return data;
#else
    need(!test_objects.empty(),"Network disabled in native test executable");
    auto name=url.substr(url.rfind('/')+1);
    if(name=="manifest.json" || name=="launcher-manifest.json") return read(test_objects/name,limit);
    return read(test_objects/"objects"/name,limit);
#endif
}
static void validate_state(const J& s) {
    exact(s,{"active","previous","highest_sequence","manifest_digest"});
    for(auto k:{"active","previous"}) {if(std::string(k)=="previous" && s[k].is_null())continue;need(s[k].is_string() && match(s[k].get<std::string>(),"[a-f0-9]{32}"),"Invalid release ID");}
    integer(s["highest_sequence"],1);need(s["manifest_digest"].is_string() && match(s["manifest_digest"].get<std::string>(),"[a-f0-9]{64}"),"Invalid manifest digest state");
}
struct Store {
    fs::path root,releases,state_file,journal;
    explicit Store(fs::path p):root(fs::absolute(p)),releases(root/"releases"),state_file(root/"current.json"),journal(root/"transaction.json") {no_links(root);no_links(releases);fs::create_directories(releases);}
    J state() {no_links(state_file);if(!fs::exists(state_file))return nullptr;auto s=read_json(state_file);validate_state(s);return s;}
    void recover() {no_links(journal);if(!fs::exists(journal))return;auto j=read_json(journal);exact(j,{"old"});if(j["old"].is_null()){no_links(state_file);fs::remove(state_file);}else{validate_state(j["old"]);atomic_json(state_file,j["old"]);}fs::remove(journal);progress("Przywrocono wersje po przerwanej aktualizacji.");}
    std::pair<Manifest,fs::path> verify_release(const std::string& id) {
        need(match(id,"[a-f0-9]{32}"),"Invalid release ID");auto path=releases/id;
        auto m=verify_manifest(read(path/"manifest.json",MAX_MANIFEST),false);std::set<std::string> allowed={"manifest.json"};
        for(const auto& e:m.doc["files"]) {auto name=e["path"].get<std::string>();auto data=read(path/fs::u8path(name));need(data.size()==integer(e["size"]) && sha(data)==e["sha256"],"File verification failed: "+name);allowed.insert(name);}
        for(auto& child:fs::recursive_directory_iterator(path)) {no_links(child.path());if(child.is_regular_file())need(allowed.count(child.path().lexically_relative(path).generic_u8string()),"Unmanaged file in release: "+child.path().u8string());}
        return {m,path};
    }
    fs::path current() {auto s=state();need(!s.is_null(),"No installed release");auto result=verify_release(s["active"]);need(result.first.digest==s["manifest_digest"] && integer(result.first.doc["sequence"])<=integer(s["highest_sequence"]),"Manifest/state mismatch");return result.second;}
    void install(const Bytes& envelope,const std::string& url) {
        auto base=endpoint(url);auto m=verify_manifest(envelope,true);auto old=state();
        if(!old.is_null() && old["manifest_digest"]==m.digest){current();return;}
        need(integer(m.doc["sequence"])>(old.is_null()?0:integer(old["highest_sequence"])),"Manifest rollback/replay rejected");
        auto id=random_id();auto stage=releases/id;no_links(stage);need(fs::create_directory(stage),"Cannot create release directory");bool activated=false;
        try {
            for(const auto& e:m.doc["files"]) {
                auto name=e["path"].get<std::string>();auto target=stage/fs::u8path(name);no_links(target);fs::create_directories(target.parent_path());Bytes data;bool reusable=false;
                if(!old.is_null()){auto previous=releases/old["active"].get<std::string>()/fs::u8path(name);no_links(previous);if(fs::is_regular_file(previous) && fs::file_size(previous)==integer(e["size"])){data=read(previous);reusable=sha(data)==e["sha256"];}}
                if(!reusable){progress("Pobieranie: "+name);data=fetch(base+"/objects/"+e["sha256"].get<std::string>(),integer(e["size"]));}
                need(data.size()==integer(e["size"]) && sha(data)==e["sha256"],"SHA256/size mismatch: "+name);write_file(target,data);
            }
            atomic_json(stage/"manifest.json",parse(envelope));verify_release(id);
            J next={{"active",id},{"previous",old.is_null()?J(nullptr):old["active"]},{"highest_sequence",m.doc["sequence"]},{"manifest_digest",m.digest}};
            atomic_json(journal,J{{"old",old}});atomic_json(state_file,next);activated=true;current();fs::remove(journal);
        }catch(...){if(fs::exists(journal))recover();else if(activated)throw;fs::remove_all(stage);throw;}
    }
    void rollback() {auto s=state();need(!s.is_null() && !s["previous"].is_null(),"No previous release");auto m=verify_release(s["previous"]);auto next=s;next["active"]=s["previous"];next["previous"]=nullptr;next["manifest_digest"]=m.first.digest;atomic_json(journal,J{{"old",s}});atomic_json(state_file,next);current();fs::remove(journal);}
};

static const char* LAUNCHER_NAMES[] = {"ZDECHLAK Launcher.exe", "ZDECHLAK.exe"};
struct LauncherSelfUpdate {
    fs::path runtime, bundle, state_file, pending_dir, helpers_dir, backup_dir, apply_journal, pending_payload, helper_exe;
    explicit LauncherSelfUpdate(fs::path runtime_root, fs::path bundle_root)
        : runtime(fs::absolute(runtime_root)), bundle(fs::absolute(bundle_root)),
          state_file(runtime/"launcher-state.json"), pending_dir(runtime/"launcher-pending"),
          helpers_dir(runtime/"helpers"), backup_dir(runtime/"launcher-backup"),
          apply_journal(runtime/"launcher-apply.json"),
          pending_payload(pending_dir/"ZDECHLAK-Launcher.exe"),
          helper_exe(helpers_dir/"zdechlak-apply.exe") {
        no_links(runtime); no_links(bundle); fs::create_directories(runtime);
    }
    J state() {
        no_links(state_file);
        if (!fs::exists(state_file)) return nullptr;
        auto s = read_json(state_file);
        exact(s, {"highest_sequence", "version", "manifest_digest", "sha256"});
        integer(s["highest_sequence"], 1);
        need(s["version"].is_string() && s["manifest_digest"].is_string() && s["sha256"].is_string(), "Invalid launcher state");
        return s;
    }
    void apply_from_pending(const J& journal) {
        exact(journal, {"expected_sha256", "sequence", "version", "manifest_digest", "backup"});
        fs::create_directories(backup_dir);
        for (auto name : LAUNCHER_NAMES) {
            auto current = bundle / name;
            if (fs::is_regular_file(current)) {
                auto data = read(current);
                auto dest = backup_dir / name;
                fs::remove(dest);
                write_file(dest, data);
            }
        }
        auto data = read(pending_payload);
        need(sha(data) == journal["expected_sha256"].get<std::string>(), "Launcher pending payload hash mismatch");
        for (auto name : LAUNCHER_NAMES) replace_file(bundle / name, data);
        atomic_json(state_file, J{
            {"highest_sequence", journal["sequence"]},
            {"version", journal["version"]},
            {"manifest_digest", journal["manifest_digest"]},
            {"sha256", journal["expected_sha256"]},
        });
        fs::remove(apply_journal);
        fs::remove_all(pending_dir);
    }
    bool recover() {
        no_links(apply_journal);
        if (!fs::exists(apply_journal)) return false;
        auto journal = read_json(apply_journal);
        if (fs::is_regular_file(pending_payload) && sha(read(pending_payload)) == journal["expected_sha256"].get<std::string>()) {
            progress("Dokonczanie aktualizacji launchera...");
            apply_from_pending(journal);
            return true;
        }
        if (journal.value("backup", false) && fs::is_directory(backup_dir)) {
            progress("Przywracanie launchera po nieudanej aktualizacji...");
            for (auto name : LAUNCHER_NAMES) {
                auto src = backup_dir / name;
                if (fs::is_regular_file(src)) replace_file(bundle / name, read(src));
            }
            fs::remove(apply_journal);
            return true;
        }
        fs::remove(apply_journal);
        return false;
    }
    bool prepare(const Bytes& envelope, const std::string& url) {
        auto base = endpoint(url);
        auto m = verify_launcher_manifest(envelope, true);
        auto old = state();
        if (!old.is_null() && old["manifest_digest"] == m.digest) return false;
        need(integer(m.doc["sequence"]) > (old.is_null() ? 0 : integer(old["highest_sequence"])), "Launcher manifest rollback/replay rejected");
        auto entry = m.doc["file"];
        fs::create_directories(pending_dir);
        fs::create_directories(helpers_dir);
        progress("Pobieranie nowego launchera...");
        auto data = fetch(base + "/objects/" + entry["sha256"].get<std::string>(), integer(entry["size"]));
        need(data.size() == integer(entry["size"]) && sha(data) == entry["sha256"].get<std::string>(), "Launcher SHA256/size mismatch");
        fs::remove(pending_payload);
        write_file(pending_payload, data);
        fs::remove(helper_exe);
        write_file(helper_exe, data);
        atomic_json(apply_journal, J{
            {"expected_sha256", entry["sha256"]},
            {"sequence", m.doc["sequence"]},
            {"version", m.doc["version"]},
            {"manifest_digest", m.digest},
            {"backup", true},
        });
        return true;
    }
};

static fs::path locate_bundle(const fs::path& module_path) {
    auto dir = module_path.parent_path();
    if (dir.filename() == "helpers" && dir.parent_path().filename() == "runtime") return dir.parent_path().parent_path();
    return dir;
}

static void spawn_helper_and_exit(const fs::path& helper, const fs::path& bundle, bool check_only) {
#ifdef _WIN32
    std::wstring command = L"\"" + helper.wstring() + L"\" --cli --apply-launcher-update --bundle \"" + bundle.wstring() + L"\"";
    if (check_only) command += L" --check-only";
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    need(CreateProcessW(helper.c_str(), &command[0], nullptr, nullptr, FALSE, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, nullptr, bundle.c_str(), &si, &pi),
         "Cannot start launcher apply helper");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
#else
    // Linux host tests apply in-process; spawn is unnecessary.
    (void)helper; (void)bundle; (void)check_only;
#endif
}

static void relaunch_main(const fs::path& bundle, bool check_only) {
    auto main_exe = bundle / "ZDECHLAK Launcher.exe";
    if (!fs::is_regular_file(main_exe)) main_exe = bundle / "ZDECHLAK.exe";
#ifdef _WIN32
    std::wstring command = L"\"" + main_exe.wstring() + L"\"";
    if (check_only) command += L" --cli --check-only";
    else command += L""; // normal GUI launch
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    need(CreateProcessW(main_exe.c_str(), &command[0], nullptr, nullptr, FALSE, 0, nullptr, bundle.c_str(), &si, &pi),
         "Cannot relaunch updated launcher");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
#else
    (void)main_exe; (void)check_only;
#endif
}

static int run(std::vector<std::string> args, fs::path module_path) {
    bool offline=false,check=false,rollback=false,apply_launcher=false;
    fs::path bundle_override;
    for(size_t i=1;i<args.size();++i) {
        auto a=args[i];
        if(a=="--offline")offline=true;
        else if(a=="--check-only")check=true;
        else if(a=="--rollback")rollback=true;
        else if(a=="--apply-launcher-update")apply_launcher=true;
        else if(a=="--cli"){}
        else if(a=="--bundle" && i+1<args.size())bundle_override=fs::u8path(args[++i]);
#ifdef ZDECHLAK_NATIVE_TEST
        else if(a=="--test-objects" && i+1<args.size())test_objects=fs::u8path(args[++i]);
#endif
        else throw std::runtime_error("Unknown or incomplete argument: "+a);
    }
    fs::path bundle = bundle_override.empty() ? locate_bundle(module_path) : fs::absolute(bundle_override);
    no_links(bundle);
    auto config=read_json(bundle/"config/updater.json");
    need(config["enabled"].is_boolean() && config["endpoint"].is_string(),"Invalid updater configuration");
    need(config.contains("channel") && config["channel"].is_string(),"Missing updater channel");
    expected_channel = config["channel"].get<std::string>();
    need(expected_channel=="prototype" || expected_channel=="test","Unsupported updater channel");
    auto url=endpoint(config["endpoint"]);
    LauncherSelfUpdate launcher_upd(bundle/"runtime", bundle);

    if (apply_launcher) {
        // Helper path: wait briefly for parent lock release, then replace EXE files.
        for (int i = 0; i < 50; ++i) {
            try {
                Lock lock(bundle/"runtime"/"launcher.lock");
                launcher_upd.recover();
                if (fs::exists(launcher_upd.apply_journal)) launcher_upd.apply_from_pending(read_json(launcher_upd.apply_journal));
                progress("Launcher zaktualizowany.");
                if (!check) relaunch_main(bundle, false);
                return 0;
            } catch (...) {
#ifdef _WIN32
                Sleep(100);
#else
                usleep(100000);
#endif
            }
        }
        throw std::runtime_error("Timed out waiting to apply launcher update");
    }

    Store store(bundle/"runtime");
    Lock lock(store.root/"launcher.lock");
    store.recover();
    launcher_upd.recover();
    if(rollback)store.rollback();
    else if(config["enabled"].get<bool>() && !offline){
        progress("Sprawdzanie podpisanej aktualizacji...");
        store.install(fetch(url+"/manifest.json",MAX_MANIFEST),url);
        bool need_launcher=false;
        try {
            need_launcher = launcher_upd.prepare(fetch(url+"/launcher-manifest.json",MAX_MANIFEST), url);
        } catch (const std::exception& e) {
            // Missing launcher manifest is allowed on older channels.
            std::string msg = e.what();
            if (msg.find("Unexpected HTTP status") == std::string::npos && msg.find("Missing regular file") == std::string::npos)
                throw;
            progress("Brak aktualizacji launchera na kanale.");
        }
        if (need_launcher) {
            progress("Przygotowano aktualizacje launchera...");
#ifdef _WIN32
            spawn_helper_and_exit(launcher_upd.helper_exe, bundle, check);
            return 0; // parent exits; helper replaces EXE then relaunches
#else
            // Host test binary applies in-process (no PE file lock).
            launcher_upd.apply_from_pending(read_json(launcher_upd.apply_journal));
            progress("Launcher zaktualizowany (test host).");
#endif
        }
    }
    else progress(offline?"Tryb offline: weryfikacja lokalnej wersji.":"Publiczny updater jest wylaczony. Weryfikacja lokalnej wersji.");
    auto release=store.current();progress("Podpis i pliki wersji sa poprawne.");if(check || rollback)return 0;
    for(auto name:{"Tibia.dat","Tibia.spr"})need(fs::is_regular_file(release/"data/things/860"/name),std::string("Brak legalnie dostarczonego pliku 8.60: ")+name);
    auto exe=release/"ZDECHLAK-client.exe";read(exe);progress("Uruchamianie ZDECHLAK OTC 1.0...");
#ifdef _WIN32
    STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};std::wstring command=L"\""+exe.wstring()+L"\"";
    if(!CreateProcessW(exe.c_str(),&command[0],nullptr,nullptr,FALSE,0,nullptr,release.c_str(),&si,&pi)){auto s=store.state();if(!s["previous"].is_null())store.rollback();throw std::runtime_error("Nie mozna uruchomic klienta Windows.");}
    CloseHandle(pi.hThread);DWORD code=1;WaitForSingleObject(pi.hProcess,INFINITE);GetExitCodeProcess(pi.hProcess,&code);CloseHandle(pi.hProcess);
    if(code!=0){auto s=store.state();if(!s["previous"].is_null())store.rollback();throw std::runtime_error("Klient zakonczyl sie bledem: "+std::to_string(code));}return 0;
#else
    throw std::runtime_error("Game execution disabled in Linux test build");
#endif
}
#ifdef _WIN32
static HWND window=nullptr,status_label=nullptr;
static LRESULT CALLBACK window_proc(HWND h,UINT msg,WPARAM w,LPARAM l){if(msg==WM_CLOSE)return 0;return DefWindowProcW(h,msg,w,l);}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int) {
    bool cli=false;try{
        int count=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&count);need(argv!=nullptr,"Cannot read command line");std::vector<std::string> args;
        for(int i=0;i<count;++i){args.push_back(utf8(argv[i]));if(args.back()=="--cli")cli=true;}LocalFree(argv);
        wchar_t module[32768];DWORD n=GetModuleFileNameW(nullptr,module,32768);need(n && n<32768,"Cannot locate launcher");fs::path module_path(std::wstring(module,n));
        if(!cli){WNDCLASSW c{};c.lpfnWndProc=window_proc;c.hInstance=instance;c.lpszClassName=L"ZDECHLAKLauncher";c.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);c.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(1));RegisterClassW(&c);
            window=CreateWindowW(c.lpszClassName,L"ZDECHLAK OTC",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,CW_USEDEFAULT,CW_USEDEFAULT,580,220,nullptr,nullptr,instance,nullptr);need(window!=nullptr,"Cannot create launcher window");
            CreateWindowW(L"STATIC",L"ZDECHLAK  /  Tibia 8.60",WS_VISIBLE|WS_CHILD,24,22,530,32,window,nullptr,instance,nullptr);
            status_label=CreateWindowW(L"STATIC",L"Weryfikacja plikow...",WS_VISIBLE|WS_CHILD,24,78,530,80,window,nullptr,instance,nullptr);ShowWindow(window,SW_SHOW);UpdateWindow(window);
            progress=[](const std::string& text){SetWindowTextW(status_label,wide(text).c_str());UpdateWindow(window);MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}
                if(text.rfind("Uruchamianie ZDECHLAK OTC",0)==0)ShowWindow(window,SW_HIDE);};}
        int result=run(args,module_path);if(window)DestroyWindow(window);return result;
    }catch(const std::exception& e){if(cli)std::cerr<<"ZDECHLAK: "<<e.what()<<std::endl;else MessageBoxW(window,wide(e.what()).c_str(),L"ZDECHLAK",MB_OK|MB_ICONERROR);if(window)DestroyWindow(window);return 1;}
}
#else
int main(int argc,char** argv){try{return run(std::vector<std::string>(argv,argv+argc),fs::absolute(argv[0]));}catch(const std::exception& e){std::cerr<<"ZDECHLAK: "<<e.what()<<std::endl;return 1;}}
#endif
