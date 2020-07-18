#pragma once

#include <string>

// Take the Base64 Secret Key and Decode in C# and use the byte array values
/*
	// Convert the Base64 String to bytes in C# and generate the array with this.
	byte[] decoded = Convert.FromBase64String(key);

	Console.Write("const char VALUE_BACKEND_SECRET[{0}] = {1}", decoded.Length+1, "{");
	foreach (byte data in decoded)
	{
		Console.Write("{0},", (int)data);
	}
	Console.WriteLine("{0}", "0};");
*/
const char VALUE_BACKEND_SECRET[33] = { 0 };

const std::string VALUE_USER_ID = "12345";