#ifndef MOCK_EXTERNAL_H
#define MOCK_EXTERNAL_H

#include <string>
#include <vector>
#include <stdint.h>

// Mock SQLite
typedef void sqlite3;
typedef void sqlite3_stmt;
#define SQLITE_OK 0
#define SQLITE_ROW 100
#define SQLITE_DONE 101
#define SQLITE_OPEN_READWRITE 0x00000002
#define SQLITE_OPEN_CREATE 0x00000004
#define SQLITE_OPEN_FULLMUTEX 0x00010000
#define SQLITE_STATIC nullptr
#define SQLITE_TRANSIENT nullptr

inline int sqlite3_open_v2(const char*, sqlite3**, int, const char*) { return SQLITE_OK; }
inline int sqlite3_close(sqlite3*) { return SQLITE_OK; }
inline int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**) { return SQLITE_OK; }
inline int sqlite3_step(sqlite3_stmt*) { return SQLITE_DONE; }
inline int sqlite3_finalize(sqlite3_stmt*) { return SQLITE_OK; }
inline const unsigned char* sqlite3_column_text(sqlite3_stmt*, int) { return (const unsigned char*)""; }
inline int sqlite3_column_int(sqlite3_stmt*, int) { return 0; }
inline int64_t sqlite3_column_int64(sqlite3_stmt*, int) { return 0; }
inline int sqlite3_bind_text(sqlite3_stmt*, int, const char*, int, void*) { return SQLITE_OK; }
inline int sqlite3_exec(sqlite3*, const char*, int (*)(void*,int,char**,char**), void*, char**) { return SQLITE_OK; }
inline void sqlite3_free(void*) {}
inline const char* sqlite3_errmsg(sqlite3*) { return "mock error"; }
inline int sqlite3_reset(sqlite3_stmt*) { return SQLITE_OK; }

// Mock CURL
typedef void CURL;
struct curl_slist { char* data; struct curl_slist* next; };
enum CURLcode { CURLE_OK = 0, CURLE_FAILED_INIT = 1 };
#define CURLOPT_URL 10002
#define CURLOPT_WRITEFUNCTION 20011
#define CURLOPT_WRITEDATA 10001
#define CURLOPT_HTTPHEADER 10023
#define CURLOPT_POSTFIELDS 10015
#define CURLOPT_TIMEOUT 10013
#define CURLOPT_CONNECTTIMEOUT 10078
#define CURLOPT_SSL_VERIFYPEER 10064
#define CURLOPT_SSL_VERIFYHOST 10081
#define CURLOPT_HTTP_VERSION 10084
#define CURL_HTTP_VERSION_2TLS 4

inline CURL* curl_easy_init() { return (CURL*)1; }
inline void curl_easy_cleanup(CURL*) {}
inline void curl_easy_reset(CURL*) {}
inline CURLcode curl_easy_setopt(CURL*, int, ...) { return CURLE_OK; }
inline CURLcode curl_easy_perform(CURL*) { return CURLE_OK; }
inline const char* curl_easy_strerror(CURLcode) { return "mock curl error"; }
inline struct curl_slist* curl_slist_append(struct curl_slist*, const char*) { return nullptr; }
inline void curl_slist_free_all(struct curl_slist*) {}

#endif
