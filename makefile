CPPFLAGS = -g -Wall -std=c++11

test-crypto: gistfile1.cpp
	g++ $(CPPFLAGS) gistfile1.cpp -I $(HOME)   -lcryptopp -o test-crypto


chain-sha256: chain_sha256.cpp
	g++ -g chain_sha256.cpp -I $(HOME)   -lcryptopp -o chain-sha256

test-sha1: test_sha1.c
	g++ -g test_sha1.c -I $(HOME)  -lcryptopp -o test_sha1


test-dh: ecdh-agree.cpp
	g++ -g -O2 -DNDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread

clean:
	rm *.bin chain-sha256 ecdh-agree.exe test-crypto test-sha256 *.dat
        
