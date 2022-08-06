// g++ -g3 -ggdb -O0 -DDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;


#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include <string>
#include <fstream>

#define TEST 1

int main( int, char** ) {

    OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;

    ECDH < ECP >::Domain dhA( CURVE ), dhB( CURVE );

    // Don't worry about point compression. Its amazing that Certicom got
    // a patent for solving an algebraic equation....
    // dhA.AccessGroupParameters().SetPointCompression(true);
    // dhB.AccessGroupParameters().SetPointCompression(true);

    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());

    dhA.GenerateKeyPair(rng, privA, pubA);
    dhB.GenerateKeyPair(rng, privB, pubB);

    cout << privA.data() << endl;

#if TEST
    string keyPath = "privA.bin";  
	std::ofstream(keyPath, std::ios::binary).write((char*)privA.data(), sizeof(privA.data()));
#endif



#if TEST
    // Read a key from a file
	// REF: https://vprog1215.tistory.com/96

	keyPath = "privA.bin";
	std::ifstream is;
     
	int keyFileSize = 0;
    is.open (keyPath, std::ios::binary);
	is.seekg(0, std::ios_base::end);//get binary file length
    keyFileSize = is.tellg();//get binary file length
    is.seekg(0, std::ios::beg);//get binary file length
    char *keybuffer = new char[keyFileSize];
    is.read(keybuffer, keyFileSize);
    is.close();
    // memcpy (key, keybuffer, keyFileSize );
    is.close();
	// Pretty print key
    cout << keybuffer << endl;
#endif 


    if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
	throw runtime_error("Shared secret size mismatch");

    SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

    const bool rtn1 = dhA.Agree(sharedA, privA, pubB);
    const bool rtn2 = dhB.Agree(sharedB, privB, pubA);
    if(!rtn1 || !rtn2)
	throw runtime_error("Failed to reach shared secret (A)");

    const bool rtn3 = sharedA.size() == sharedB.size();
    if(!rtn3)
	throw runtime_error("Failed to reach shared secret (B)");

    Integer a, b;

    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    cout << "(A): " << std::hex << a << endl;

    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    cout << "(B): " << std::hex << b << endl;

    const bool rtn4 = a == b;
    if(!rtn4)
	throw runtime_error("Failed to reach shared secret (C)");

    cout << "Agreed to shared secret" << endl;

    return 0;
}
