#include <stdio.h>
#include <stdlib.h>
#include <math.h>       /* pow */
#include <random>

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include <mpi.h>

string decode(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	string recovered;
	decryptor.SetKeyWithIV(key, 8, iv);
	StringSource s(cipher, true, 
		new StreamTransformationFilter(decryptor,
			new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING 
		) // StreamTransformationFilter
	); // StringSource
	return recovered;
}

bool check_key(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	return decode(decryptor, cipher, key, iv).find("esperemos") != std::string::npos;	
}

int main(int argc, char* argv[]) {
	AutoSeededRandomPool prng;

	SecByteBlock key(8);
	prng.GenerateBlock(key, 8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	// prng.GenerateBlock(iv, sizeof(iv));
	CryptoPP::byte key2[DES::KEYLENGTH] = {250, 255, 255, 255, 255, 255, 255, 223};

	string plain = "Este es la cadena de prueba, esperemos encontrar un resultado apropiado";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

    // cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
    // cout << "block size: " << DES::BLOCKSIZE << endl;

	// Pretty print key
	encoded.clear();
	StringSource(key2, 8, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	// cout << "key: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		// cout << "plain text: " << plain << endl;

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, 8, iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	// cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		unsigned char cipherSom[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};
		int N, id;
		uint64_t upper = (uint64_t)(pow(2, 56)); //upper bound DES keys 2^56
		uint64_t mylower, myupper;
		MPI_Status st;
		MPI_Request req;
		int flag;
		int ciphlen = *(&cipherSom + 1) - cipherSom;
		MPI_Comm comm = MPI_COMM_WORLD;
		MPI_Init(NULL, NULL);
		MPI_Comm_size(comm, &N);
		MPI_Comm_rank(comm, &id);
		long int range_per_node = upper / N;
  		mylower = range_per_node * id;
  		myupper = range_per_node * (id+1) -1;
  		if(id == N-1){
    	//compensar residuo
    		myupper = upper;
  		}

  		long found = 0;

  		MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
		// cout << " Something: " << id << " lower: " << mylower << " upper: " << myupper << ";";

		CBC_Mode< DES >::Decryption d;
		//long int x = 4294967296;
		uint64_t x = 0;
		unsigned char arrayOfByte[8];
		memcpy(arrayOfByte, &mylower, 8);
		cout << "Checking " << id << " " << (int)arrayOfByte[0] << (int)arrayOfByte[1] << (int)arrayOfByte[2] << (int)arrayOfByte[3] << (int)arrayOfByte[4] << (int)arrayOfByte[5] << (int)arrayOfByte[6] << (int)arrayOfByte[7] << "\n";

		bool is_key = false;
		std::default_random_engine generator;
		std::uniform_int_distribution<uint64_t> distribution(mylower, myupper);

		while (!is_key) {
			uint64_t rand_i = distribution(generator);  // generates number in the range mylower..myupper
			memcpy(arrayOfByte, &rand_i, 8);
			is_key = check_key(d, cipher, arrayOfByte, iv);

			if (is_key) {
				found = 15;
				cout << "Found " << id << "\n";
				cout << "Checking " << id << " " << (int)arrayOfByte[0] << (int)arrayOfByte[1] << (int)arrayOfByte[2] << (int)arrayOfByte[3] << (int)arrayOfByte[4] << (int)arrayOfByte[5] << (int)arrayOfByte[6] << (int)arrayOfByte[7] << "\n";
				for(int node=0; node<N; node++){
					MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
				}
			}

			MPI_Test(&req, &flag, &st);
			if (found)
				break;
		}

		MPI_Finalize();
		return 0;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}