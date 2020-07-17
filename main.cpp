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
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include <Windows.h>

// Ref: https://github.com/Thalhammer/jwt-cpp
#undef max
#undef min 
#include <jwt-cpp/jwt.h>

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

string DoJWT(string userId)
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
        .set_payload_claim("", jwt::claim(strJson))
        .sign(jwt::algorithm::hs256{ secret });

    return token.c_str();
}

void DoPost()
{
    using ostream = Concurrency::streams::ostream;
    using fstream = Concurrency::streams::fstream;

    auto fileStream = std::make_shared<ostream>();

    // Open stream to output file.
    pplx::task<void> requestTask = fstream::open_ostream(U("results.html")).then([=](ostream outFile)
    {
        *fileStream = outFile;

        // Create http_client to send the request.
        http_client client(U("http://www.bing.com/"));

        // Build request URI and start the request.
        uri_builder builder(U("/search"));
        builder.append_query(U("q"), U("cpprestsdk github"));
        return client.request(methods::GET, builder.to_string());
    })

    // Handle response headers arriving.
    .then([=](http_response response)
    {
        printf("Received response status code:%u\n", response.status_code());

        // Write response body into the file.
        return response.body().read_to_end(fileStream->streambuf());
    })

    // Close the file stream.
    .then([=](size_t)
    {
        return fileStream->close();
    });

    // Wait for all the outstanding I/O to complete and handle any exceptions
    try
    {
        requestTask.wait();
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

    string token = DoJWT("12345");
    cout << "Token: " << token << endl;

    DoPost();
}


#pragma comment (lib, "bcrypt")
#pragma comment (lib, "crypt32")
#pragma comment (lib, "winhttp")

#ifdef _DEBUG
#pragma comment (lib, "cpprest142_2_10d")
#else
#pragma comment (lib, "cpprest142_2_10")
#endif
