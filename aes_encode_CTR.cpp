#include<sstream>
#include<string>
#include <cryptopp/osrng.h>
#include<cryptopp/modes.h>
using namespace std;

#include"cryptopp/cryptlib.h"
#include"cryptopp/hex.h"
#include"cryptopp/filters.h"
#include"cryptopp/des.h"
#include"cryptopp/aes.h"
#include"cryptopp/modes.h"
#include <fstream>
#include <iostream>

using namespace CryptoPP;
string aes_encode(string &plain, byte key[], byte iv[])
{
    string cipher;

    if (plain.empty()) {
        cerr << "Error: Plaintext cannot be empty." << endl;
        return "";
    }

    try {
        CTR_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

        byte *plainBytes = new byte[plain.size()];
        std::copy(plain.begin(), plain.end(), plainBytes);

        CryptoPP::StringSink sink(cipher);
        CryptoPP::StreamTransformationFilter s(enc, new CryptoPP::StringSink(sink));
        s.Put(plainBytes, plain.size());
        s.MessageEnd();

        delete[] plainBytes;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << "AES_CTR_Encryption: " << e.what() << endl;
        cout << "Error: " << e.what() << endl;
        return "";
    }

    return cipher;
}
int main(int argc, char * argv[])
{
    fstream file1;
    fstream file2;
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];

    if (argc != 5)
    {
        cout << "usage:aes_encode_CTR infile outfile key iv" << endl;
        return 0;
    }

    // read key and iv from input
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
    {
        if (argv[3][i] != '\0')
        {
            key[i] = (byte)argv[3][i];
        }
        else
        {
            break;
        }
    }

    if (AES::DEFAULT_KEYLENGTH != 16 && AES::DEFAULT_KEYLENGTH != 32)
    {
        cerr << "Key length must be 16 or 32 bytes" << endl;
        return 1;
    }

    for (int i = 0; i < AES::BLOCKSIZE; i++)
    {
        if (argv[4][i] != '\0')
        {
            iv[i] = (byte)argv[4][i];
        }
        else
        {
            break;
        }
    }
    // encode
    string cipher;
    file1.open(argv[1],ios::in);
	//reading
	stringstream buffer;  
	buffer << file1.rdbuf();  
	string plain(buffer.str());
    cipher = aes_encode(plain, key, iv);
    file1.close();
    file2.open(argv[2], ios::out);
    std::string ciphertext_hex = "";
    CryptoPP::HexEncoder encoder;
    CryptoPP::StringSink ss_hex(cipher);
    encoder.Attach(new CryptoPP::Redirector(ss_hex));
    encoder.Put(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
    encoder.MessageEnd();
    ss_hex.Get((byte*)ciphertext_hex.data(), ciphertext_hex.size());
    file2 << cipher;
    
    file2.close();
    cout << "key: ";
    string encoded;
    encoded.clear();
    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
    cout << encoded << endl;

    cout << "IV: ";
    encoded.clear();
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
    cout << encoded << endl;
    cout << endl;

    cout << "cipher text: " << cipher << endl;


    return 0;
}