#include <string>


#include <cstdio>
#include <iostream>
using namespace std;

#include <crypto++/sha.h>
#include <crypto++/filters.h>
#include <crypto++/base64.h>
#include <crypto++/osrng.h>

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <crypto++/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <crypto++/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <crypto++/aes.h>
using CryptoPP::AES;
using namespace CryptoPP;

#include <cryptopp/blowfish.h>
#include <cryptopp/eax.h>


#define TEST 1

int timestamp = 0;
byte key[AES::DEFAULT_KEYLENGTH];
byte iv[AES::BLOCKSIZE];


std::string SHA256HashString(std::string aString){
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(aString, true,
    new CryptoPP::HashFilter(hash,
      new CryptoPP::Base64Encoder (
         new CryptoPP::StringSink(digest))));

    return digest;
}

std::string SHA256HashStringFromFile(string ofilename)
{
	 
    std::string digest;
    CryptoPP::SHA256 hash;

	try {

       /*********************************\
       \*********************************/
	   
	   FileSource fs1(ofilename.c_str(), true,
           new CryptoPP::HashFilter(hash,
             new CryptoPP::Base64Encoder (
                new CryptoPP::StringSink(digest))));  
				   
	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
    }
    return digest;

}


string chain(string prev, string val) {
    SHA256 hash;
    byte digest[CryptoPP::SHA256::DIGESTSIZE];

    if (prev =="")  {
        return SHA256HashString(val);
    }
    else  {
        cout << "prev hash : " << prev << endl;
        return SHA256HashString( prev +chain("", val)) ;
    } 
}

int epoch(){
    return ++timestamp;
}


void CBC_keygen()
{
	AutoSeededRandomPool prng;
	
	//byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	//byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;
	
#if TEST
    string keyPath = "key.bin";  
	ofstream(keyPath, ios::binary).write((char*)key, sizeof(key));
#endif

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

#if TEST 
    string ivPath = "iv.bin";  
	ofstream(ivPath, ios::binary).write((char*)iv, sizeof(iv));
#endif

}

void getKeyIV_From_File(string keyPath)
{

    AutoSeededRandomPool prng;
	string cipher, encoded, recovered;
   

	// string keyPath = "key.bin";
	ifstream is;
	int keyFileSize = 0;
    is.open (keyPath, ios::binary);
	is.seekg(0, ios_base::end);//get binary file length
    keyFileSize = is.tellg();//get binary file length
    is.seekg(0, ios::beg);//get binary file length
    char *keybuffer = new char[keyFileSize];
    is.read(keybuffer, keyFileSize);
    is.close();
    memcpy (key, keybuffer, keyFileSize );
    is.close();
	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key(file): " << encoded << endl;

}

string EncryptImage(string ofilename)
{

	string efilename = "puppy-and-teddy.enc";
	try {

       /*********************************\
       \*********************************/
	   
	   EAX< Blowfish >::Encryption e1;
	   e1.SetKeyWithIV(key, sizeof(key), iv);
	   
	   FileSource fs1(ofilename.c_str(), true,
            new AuthenticatedEncryptionFilter(e1,
                new FileSink(efilename.c_str())
            ) );
				   
		/*********************************\
        \*********************************/
		
	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
    }

    return efilename;

}


string decryptImage(string efilename)
{
	
	string rfilename = "puppy-and-teddy-recovered.jpg";
	try {

	    /*********************************\
        \*********************************/	
		EAX< Blowfish >::Decryption d2;
        d2.SetKeyWithIV(key, sizeof(key), iv);
		FileSource fs2(efilename.c_str(), true,
            new AuthenticatedDecryptionFilter( d2,
                new FileSink( rfilename.c_str() ),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION
					)
		);		   
		/*********************************\
        \*********************************/
		
	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
    }
    return rfilename;

}


int  main()
{

    CBC_keygen();

    string keyPath = "key.bin";
    getKeyIV_From_File(keyPath);
    keyPath = "iv.bin";
    getKeyIV_From_File(keyPath);
    
    string s1 = "abc";
    string x = chain("", s1);
    cout << epoch() << " : " << x << endl;

#if TEST
    /*********************************\
    \*********************************/
    cout << ">> Frame is added" << endl;
    string ofilename = "eukanuba-market-image-puppy-beagle.jpeg";
    string s2 = SHA256HashStringFromFile(ofilename);
    x = chain(x, s2);
    cout << epoch() << " : " << x << endl;

    /*********************************\
    \*********************************/
    cout << ">> Frame is encrypted" << endl;

    ofilename = "eukanuba-market-image-puppy-beagle.jpeg";
    ofilename = EncryptImage(ofilename);
    s2 = SHA256HashStringFromFile(ofilename);
    x = chain(x, s2);

    //  문자 스트링을 long integer 값으로 변환
    long int msgHash = strtol(s2.c_str(), NULL, 16);
    cout << "MSB : " << msgHash << endl;

    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++)
         std::cout << std::hex << (int)s2[i] << std::dec;
    std::cout << endl;


    cout << epoch() << " : " << x << endl;

    /*********************************\
    \*********************************/
    cout << ">> Frame is decrypted" << endl;
	string efilename = "puppy-and-teddy.enc";
    ofilename = decryptImage(efilename);
    s2 = SHA256HashStringFromFile(ofilename);
    x = chain(x, s2);
    cout << epoch() << " : " << x << endl;

#else    
    string s2 = "def";
    x = chain(x, s2);
#endif
    
    string s3 = "ghi";
    x = chain(x, s3);
    cout << epoch() << " : " << x << endl;
    x = chain("", x);
    cout << epoch() << " : " << x << endl;

    
    
    return 0;

}