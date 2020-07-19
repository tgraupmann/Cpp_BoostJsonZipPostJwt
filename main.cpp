// Cpp_BoostJsonZipPostJwt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>
#include <sstream>
#include <iostream>
#include <istream>
#include <ostream>

#include "Secret.h"
#include <json/json.h>

#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

#include <cpprest/http_client.h>

#include <Windows.h>

// Ref: https://github.com/Thalhammer/jwt-cpp
#undef max
#undef min 
#include <jwt-cpp/jwt.h>
#include "picojson/picojson.h"

using namespace std;

//cpprestsdk
using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

#include <tchar.h>

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

string DoBase64Decode(const string& text)
{
    using namespace boost::archive::iterators;

    std::stringstream os;
    bool bPaded = false;
    typedef boost::archive::iterators::transform_width<boost::archive::iterators::
        binary_from_base64<const char*>, 8, 6> Base64DecodeIterator;

    int iLength = text.size();
    // Remove the padding characters, cf. https://svn.boost.org/trac/boost/ticket/5629
    if (iLength && text.c_str()[iLength - 1] == '=') {
        bPaded = true;
        --iLength;
        if (iLength && text.c_str()[iLength - 1] == '=')
        {
            --iLength;
        }
    }
    if (iLength == 0)
    {
        return "";
    }

    if (bPaded)
    {
        iLength--;
    }

    std::copy(Base64DecodeIterator(
        text.c_str()),
        Base64DecodeIterator(text.c_str() + iLength),
        std::ostream_iterator<char>(os));

    return os.str();
}

string DoJWT(string userId, string secret)
{
    Json::FastWriter fastWriter;

    time_t t = time(NULL);
    struct tm offset_epoch;
    localtime_s(&offset_epoch, &t);
    long offsetMinutes = offset_epoch.tm_min;
    
    auto future = std::chrono::system_clock::now() + std::chrono::minutes{ 120 - offsetMinutes };
    auto exp = std::chrono::duration_cast<std::chrono::seconds>(future.time_since_epoch()).count();

    cout << "EXP: " << exp << endl;

    picojson::array jsonSend;
    picojson::object jsonPerms;
    jsonSend.push_back(picojson::value("*"));
    jsonPerms["send"] = picojson::value(jsonSend);

    auto token = jwt::create()
        .set_type("JWT")
        .set_expires_at(future)
        .set_payload_claim("channel_id", jwt::claim(userId))
        .set_payload_claim("user_id", jwt::claim(userId))
        .set_payload_claim("role", jwt::claim(string("external")))
        .set_payload_claim("pubsub_perms", jwt::claim(picojson::value(jsonPerms)))
        .sign(jwt::algorithm::hs256{ secret });

    return token.c_str();
}

void DoPost()
{
    // Wait for all the outstanding I/O to complete and handle any exceptions
    try
    {
        // Create http_client to send the request.
        http_client client(U("https://tagenigma.com/"));

        // Build request URI and start the request.
        uri_builder builder(U("/post"));
        client.request(methods::POST, builder.to_string())

        // Handle response headers arriving.
        .then([=](http_response response)
        {
            printf("Received response status code:%u\n", response.status_code());
            return response.extract_string(true);
        })
        .then([=](wstring content)
        {
            wcout << L"Content: " << content << endl;
        })
        .wait();
    }
    catch (const std::exception& e)
    {
        printf("Error exception:%s\n", e.what());
    }
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

    string unBase64 = DoBase64Decode(base64);
    cout << "Unbase64 Size: " << unBase64.size() << endl;
    cout << "Unbase64: " << unBase64 << endl;

    cout << "Secret: " << DoBase64Encode(VALUE_BACKEND_SECRET) << endl;

    // works
    string jwtToken = DoJWT(VALUE_USER_ID, VALUE_BACKEND_SECRET);
    cout << "JWT Token: " << jwtToken << endl;

    DoPost();
}


#pragma comment (lib, "bcrypt")
#pragma comment (lib, "crypt32")
#pragma comment (lib, "winhttp")

#ifdef _DEBUG
#pragma comment (lib, "cpprest142_2_10d")
#pragma comment (lib, "libcryptod")
#pragma comment (lib, "libssld")
#else
#pragma comment (lib, "cpprest142_2_10")
#pragma comment (lib, "libcrypto")
#pragma comment (lib, "libssl")
#endif
