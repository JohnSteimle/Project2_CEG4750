#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
using namespace std;

#include"cryptopp/cryptlib.h"
#include"cryptopp/hex.h"
#include"cryptopp/filters.h"
#include"cryptopp/des.h"
#include"cryptopp/aes.h"
#include"cryptopp/modes.h"
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

string aes_decode(string & cipher, byte key[], byte iv[])
{
    string plain;
    std::string ciphertext_hex = "";
    CryptoPP::HexEncoder encoder;
    CryptoPP::StringSink encoder_sink(cipher);
    CryptoPP::StringSource encoder_source(cipher, true, new CryptoPP::Redirector(encoder));
    encoder.Attach(new CryptoPP::Redirector(encoder_sink));
    encoder.MessageEnd();
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    byte ciphertext_bytes[ciphertext_hex.length()/2];
    StringSource ss(ciphertext_hex, true, new HexDecoder);
    ss.Detach(new ArraySink(ciphertext_bytes, sizeof(ciphertext_bytes)));
    StreamTransformationFilter stf(dec, new StringSink(plain));
    stf.Put(ciphertext_bytes, sizeof(ciphertext_bytes));
    stf.MessageEnd();
    
    return plain;
}

int main(int argc, char * argv[])
{
    fstream file1;
    fstream file2;
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    if(argc!=5)
    {
        cout<<"usage:aes_decode infile outfile key iv"<<endl;
        return 0;
    }
    file1.open(argv[1],ios::in);
    file2.open(argv[2],ios::out);
    //reading
    stringstream buffer;
    buffer << file1.rdbuf();
    string cipher(buffer.str());
    //get key
    memset(key,0,AES::DEFAULT_KEYLENGTH);
    for(int i=0;i<AES::DEFAULT_KEYLENGTH;i++)
    {
        if(argv[3][i]!='\0')
        {
            key[i]=(byte)argv[3][i];
        }
        else
        {
            break;
        }
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
    //print key
    string encoded;
    encoded.clear();
    StringSource(key, sizeof(key), true, new HexEncoder( new StringSink(encoded)));
    cout << "key: " << encoded<< endl;
    encoded.clear();
    StringSource(iv, sizeof(iv), true, new HexEncoder( new StringSink(encoded)));
    cout << "iv: " << encoded<< endl;
    //decode
    string plain=aes_decode(cipher,key, iv);
    cout << "recovered text: " << plain<< endl;
    file2<<plain;
    cout<<"plain text stored in:"<<argv[2]<<endl;
}