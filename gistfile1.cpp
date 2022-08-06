//Generate an RSA key pair, sign a message and verify it using crypto++ 5.6.1 or later.
//By Tim Sheerman-Chase, 2013
//This code is in the public domain and CC0
//To compile: g++ gen.cpp -lcrypto++ -o gen

#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>


using namespace CryptoPP;

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


#include <crypto++/aes.h>
using CryptoPP::AES;

#include <crypto++/ccm.h>
using CryptoPP::CBC_Mode;

#include <crypto++/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <cryptopp/blowfish.h>
#include <cryptopp/eax.h>

#include <cstdio>
#include <ctime>
#include <time.h>




byte key[AES::DEFAULT_KEYLENGTH];
byte iv[AES::BLOCKSIZE];


#define TEST 1

std::string SHA256HashString(std::string aString){
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource foo(aString, true,
    new CryptoPP::HashFilter(hash,
      new CryptoPP::Base64Encoder (
         new CryptoPP::StringSink(digest))));

    return digest;
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
}

string Encrypt(string plain)
{

    AutoSeededRandomPool prng;
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/
	try
	{
		cout << "plain text: " << plain << endl;
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);


#if TEST
    // Read a key from a file
	// REF: https://vprog1215.tistory.com/96

	string keyPath = "key.bin";
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

	// set the key which is read from the key file
	e.SetKeyWithIV(key, sizeof(key), iv);
#endif 

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	return encoded;

	/*********************************\
	\*********************************/

}


void Decrypt(string cipher)
{
	/*********************************\
	\*********************************/

	string encoded, recovered;
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		/*
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		*/

        // https://stackoverflow.com/questions/18945622/aes-decryption-and-invalid-pkcs-7-block-padding
		CryptoPP::StringSource ss(cipher, true,
        new CryptoPP::HexDecoder(
        new CryptoPP::StreamTransformationFilter( d,
            new CryptoPP::StringSink( recovered ) ) ) );

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	/*********************************\
	\*********************************/
}


void GenKeyPair()
{
	// InvertibleRSAFunction is used directly only because the private key
	// won't actually be used to perform any cryptographic operation;
	// otherwise, an appropriate typedef'ed type from rsa.h would have been used.
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	 
	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(privkey);
	
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

}

void Sign(string strContents)
{
	//string strContents = "A message to be signed";
	//FileSource("tobesigned.dat", true, new StringSink(strContents));
	
	AutoSeededRandomPool rng;
	
	//Read private key
	CryptoPP::ByteQueue bytes;
	FileSource file("privkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);

	//Sign message
	RSASSA_PKCS1v15_SHA_Signer privkey(privateKey);
	SecByteBlock sbbSignature(privkey.SignatureLength());
	privkey.SignMessage(
		rng,
		(byte const*) strContents.data(),
		strContents.size(),
		sbbSignature);

	//Save result
	FileSink sink("signed.dat");
	sink.Put((byte const*) strContents.data(), strContents.size());
	FileSink sinksig("sig.dat");
	sinksig.Put(sbbSignature, sbbSignature.size());
}

void Verify()
{
	//Read public key
	CryptoPP::ByteQueue bytes;
	FileSource file("pubkey.txt", true, new Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PublicKey pubKey;
	pubKey.Load(bytes);

	RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

	//Read signed message
	string signedTxt;
	FileSource("signed.dat", true, new StringSink(signedTxt));
	string sig;
	FileSource("sig.dat", true, new StringSink(sig));

	string combined(signedTxt);
	combined.append(sig);

	//Verify signature
	try
	{
		StringSource(combined, true,
			new SignatureVerificationFilter(
				verifier, NULL,
				SignatureVerificationFilter::THROW_EXCEPTION
		   )
		);
		cout << "Signature OK" << endl;
		cout << "signed text : " << signedTxt << endl;
		Decrypt(signedTxt);
	}
	catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
	{
		cout << err.what() << endl;
	}

}

std::string string_to_hex(const std::string& input)
{
  static const char* const lut = "0123456789ABCDEF";
  size_t len = input.length();

  std::string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; ++i)
  {
    const unsigned char c = input[i];
    output.push_back(lut[c >> 4]);
    output.push_back(lut[c & 15]);
  }
  return output;
}

std::string SHA256_1(std::string data)
{
  CryptoPP::byte const* pbData = (CryptoPP::byte*)data.data();
  unsigned int nDataLen = data.length();
  CryptoPP::byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

  CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

  // return string((char*)abDigest);  -- BAD!!!
  return std::string((char*)abDigest, CryptoPP::SHA256::DIGESTSIZE);
}

void EncryptImage_1()
{
	AutoSeededRandomPool prng;
	SecByteBlock key(Blowfish::DEFAULT_KEYLENGTH);
	prng.GenerateBlock( key, key.size() );
	
	byte iv[ Blowfish::BLOCKSIZE ];
	prng.GenerateBlock( iv, sizeof(iv) );
	
	string ofilename = "eukanuba-market-image-puppy-beagle.jpeg";
	string efilename = "puppy-and-teddy.enc";
	string rfilename = "puppy-and-teddy-recovered.jpg";
	
	try {

       /*********************************\
       \*********************************/
	   
	   EAX< Blowfish >::Encryption e1;
	   e1.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
	   
	   FileSource fs1(ofilename.c_str(), true,
            new AuthenticatedEncryptionFilter(e1,
                new FileSink(efilename.c_str())
            ) );
				   
		/*********************************\
        \*********************************/
		
		EAX< Blowfish >::Decryption d2;
		d2.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );
		FileSource fs2(efilename.c_str(), true,
            new AuthenticatedDecryptionFilter( d2,
                new FileSink( rfilename.c_str() ),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION
					)
		);
	} catch (const Exception& ex) {
		cerr << ex.what() << endl;
    }

}

#include <cryptopp/ida.h>
#include <cryptopp/channels.h>

void SecretShareFile1(int threshold, int nShares, const char *filename, const char *seed)
{
    RandomPool rng;
    rng.IncorporateEntropy((byte *)seed, strlen(seed));

    ChannelSwitch *channelSwitch;
    FileSource source(filename, false, new SecretSharing(rng,
        threshold, nShares, channelSwitch = new ChannelSwitch));

    vector_member_ptrs<FileSink> fileSinks(nShares);
    string channel;
    for (int i=0; i<nShares; i++)
    {
        char extension[5] = ".000";
        extension[1]='0'+byte(i/100);
        extension[2]='0'+byte((i/10)%10);
        extension[3]='0'+byte(i%10);
        fileSinks[i].reset(new FileSink((string(filename)+extension).c_str()));

        channel = WordToString<word32>(i);
        fileSinks[i]->Put((byte *)channel.data(), 4);
        channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
    }

    source.PumpAll();
}

//std::vector<CryptoPP::byte> SecretShareFile(int threshold, int nShares, std::string secret) {
std::vector<std::string> SecretShareFile(int threshold, int nShares, std::string secret) {

	// Some asserts on shares
	CRYPTOPP_ASSERT(nShares >= 1 && nShares<=1000);
	if (nShares < 1 || nShares > 1000) {
		throw CryptoPP::InvalidArgument("SecretShareFile: shares must be in range [1, 1000]");
	}

	// rng
	CryptoPP::AutoSeededRandomPool rng;
	
	// modify our string into cryptopp vector
	std::vector<CryptoPP::byte> secVec(secret.begin(), secret.end());
	std::vector<CryptoPP::byte> shareVec(nShares);

	// initialize channelswitch (moves data from source to sink through filters)
	CryptoPP::ChannelSwitch *channelSwitch;

	// typedef of StringSource( byte *string, size_t length, pumpall, BufferedTransformation)
	// create a source that uses our secret, and puts a filter (secret sharing) to move the
	// data using our channel switch above
	CryptoPP::VectorSource source(secVec, false,	new CryptoPP::SecretSharing(
			rng,
			threshold,
			nShares,
			channelSwitch = new CryptoPP::ChannelSwitch
		)
	);


	// from ida example, just use string instead of vector
	std::vector<std::string> strShares(nShares);
    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(nShares);

	// my understanding is this is like a base unit of how cryptopp does computation
	//std::vector<CryptoPP::SecByteBlock> shares( nShares );
	// this will be our output storage after data moves through the filter
	//vector_member_ptrs<CryptoPP::VectorSink> arraySinks( nShares );

	std::string channel;


	// based on the number of shares to generate, we know go through and do the computation
	for (int i = 0; i < nShares; i++)	{
		// creates a new StringSink set to shares[i]
		strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
		//arraySinks[i].reset( new CryptoPP::VectorSink( shareVec[i] ) );

		channel = CryptoPP::WordToString<CryptoPP::word32>(i);
        //arraySinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
        strSinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
 		//channelSwitch->AddRoute( channel,*arraySinks[i], DEFAULT_CHANNEL );
 		channelSwitch->AddRoute( channel,*strSinks[i], CryptoPP::DEFAULT_CHANNEL );
	}

	source.PumpAll();

	return strShares;
}


std::string SecretRecoverFile(int threshold, std::vector<std::string> shares) {
	CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
	if (threshold < 1 || threshold > 1000) {
		throw CryptoPP::InvalidArgument("SecretRecoverFile: shares must be in range [1, 1000]");
	}

	std::string secret;
	CryptoPP::SecretRecovery recovery(threshold, new CryptoPP::StringSink(secret));

	//vector_member_ptrs<FileSource> fileSources(threshold);
    CryptoPP::vector_member_ptrs<CryptoPP::StringSource> strSources(threshold);

	CryptoPP::SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		strSources[i].reset(new CryptoPP::StringSource(shares[i], false));
		strSources[i]->Pump(4);
		strSources[i]->Get(channel, 4);
		strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (strSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			strSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		strSources[i]->PumpAll();

	return secret;
}


int main()
{    

    cout << "SHA256 of A : " << SHA256HashString("A") << endl;
	cout << "SHA256 of A : " << string_to_hex(SHA256_1("A")) << std::endl;

    cout << "Encrypt/Decrypt image file" << endl;
    clock_t start = clock();
	EncryptImage_1();
	double timeTaken = double(::clock() - start) / CLOCKS_PER_SEC;
	cout << "elapsed time : " << timeTaken << " sec" << endl;

    string plain = "CBC Mode Test";
	CBC_keygen();
	string cipher = Encrypt(plain);
	Decrypt(cipher);

	GenKeyPair();
	cout << ">> Signing ciper " << endl;
	Sign(cipher);
	cout << ">> Verifying ciper " << endl;
	Verify();

    // https://pulwar.isi.edu/lincoln/c-samir/-/blob/main/samir-test.c
	// https://pulwar.isi.edu/lincoln/c-samir/-/blob/main/click-version.c
	char char_secret[200] = "04700000000104700000010108004500005405db40004001b37ac0a80001c0a80002080031b7000376f445002062000000001f1c0c0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
    //char char_secret[5] = "test";
	
	std::string secret(char_secret);
	std::cout << "secret: " << secret << "\n\t" << "size: " << sizeof(secret) << "\n\n";
	//std::vector<CryptoPP::byte> vec = SecretShareFile(2,3, "test.txt");
	std::vector<std::string> vec = SecretShareFile(2,3, secret);
	for ( auto &share : vec ) {
	    std::cout << "coded: " << share << "\n\t" << "size: " << sizeof(share) << "\n\n";
	}
	

	std::string decoded = SecretRecoverFile(2, vec);
	std::cout << "decoded: " << decoded << "\n";
	assert(secret.compare(decoded)==0);

}


