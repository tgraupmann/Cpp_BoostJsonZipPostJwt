// Cpp_BoostJsonZipPostJwt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <sstream>

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

#define NOMINMAX
#include <Windows.h>

// Ref: https://github.com/Thalhammer/jwt-cpp
#undef max
#undef min 
#include <jwt-cpp/jwt.h>

#include "Secret.h"
#include <json/json.h>

using namespace std;

string DoCompression(const string& data)
{
    namespace bio = boost::iostreams;

    std::stringstream compressed;
    std::stringstream origin(data);

    bio::filtering_streambuf<bio::input> out;
    out.push(bio::gzip_compressor(bio::gzip_params(bio::gzip::best_compression)));
    out.push(origin);
    bio::copy(out, compressed);

    string message = compressed.str();
    return message;
}

string DoBase64Encode(const string& text)
{
    using namespace boost::archive::iterators;

    std::stringstream os;
    typedef
        base64_from_binary<    // convert binary values to base64 characters
        transform_width<   // retrieve 6 bit integers from a sequence of 8 bit bytes
        const char*,
        6,
        8
        >
        >
        base64_text; // compose all the above operations in to a new iterator

    std::copy(
        base64_text(text.c_str()),
        base64_text(text.c_str() + text.size()),
        std::ostream_iterator<char>(os)
    );

    return os.str();
}

void DoJWT(string userId)
{
    string secret = VALUE_BACKEND_SECRET;
    int mod4 = secret.size() % 4;
    if (mod4 > 0)
    {
        secret += string('=', 4 - mod4);
    }


    Json::FastWriter fastWriter;
    

    Json::Value jsonSubject;
    jsonSubject["user_id"] = userId;
    jsonSubject["role"] = "external";
    string strSubject = fastWriter.write(jsonSubject);

    auto future = std::chrono::system_clock::now() + std::chrono::hours{ 48 };
    auto exp = std::chrono::duration_cast<std::chrono::microseconds>(future.time_since_epoch()).count();

    Json::Value jsonPayload;
    jsonPayload["exp"] = exp;
    jsonPayload["channel_id"] = userId;
    jsonPayload["user_id"] = userId;
    jsonPayload["role"] = "external";
    jsonPayload["pubsub_perms"]["send"][0] = "*";
    string strJson = fastWriter.write(jsonPayload);

    auto token = jwt::create()
        .set_issuer("Twitch")
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(future)
        .set_type("JWS")
        .set_subject(strSubject)
        .set_payload_claim("sample", jwt::claim(strJson))
        .sign(jwt::algorithm::hs256{ secret });

    cout << "Token: " << token.c_str() << endl;
}

int main()
{
    string uncompressed = "Hello World! Hello Hello Hello Hello Hello";
    cout << "Uncompressed Size: " << uncompressed.size() << endl;
    cout << "Uncompressed: " << uncompressed << endl;

    string compressed = DoCompression(uncompressed);
    cout << "Compressed Size: " << compressed.size() << endl;
    cout << "Compressed: " << compressed << endl;

    string base64 = DoBase64Encode(compressed);
    cout << "Base64 Size: " << base64.size() << endl;
    cout << "Base64: " << base64 << endl;

    DoJWT("12345");
}
