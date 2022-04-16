#include "..\..\cryptopp\cryptlib.h"
#include "..\..\cryptopp\rijndael.h"
#include "..\..\cryptopp\modes.h"
#include "..\..\cryptopp\files.h"
#include "..\..\cryptopp\osrng.h"
#include "..\..\cryptopp\hex.h"

#include <iostream>
#include <string>
#include <fstream>

using namespace std;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    HexEncoder encoder;

    string keyStr = "01030507090A0C0E";
    SecByteBlock key(reinterpret_cast<const byte*>(&keyStr[0]), keyStr.size());
    string ivStr = "05030507090A0C0A";
    SecByteBlock iv(reinterpret_cast<const byte*>(&ivStr[0]), ivStr.size());

    string cipher, recovered;

    fstream newfile;
    newfile.open("..\\..\\3D_model.obj", ios::in);
    ofstream fout; 

    
    string plain = "";
    if (newfile.is_open())
    {
        cout << "Readng File...";
        string tp;
        while (getline(newfile, tp))
        {
            plain.append(tp+"\n");
        }
        cout << "Done" << endl;
    }
    fout.close();

    cout << "Started Encryption...";
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        StringSource s(plain, true,
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) 
        ); 
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    cout << "Done" << endl;
    
    cout << "Saving encrypted file...";
    fout.open("..\\..\\encryption.aes");
    fout << cipher;
    fout.close();
    cout << "Done" << endl;

    // Decryption
    cout << "Started Decrypting data...";
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        StringSource s(cipher, true,
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            )
        );
        ofstream fout;
        cout << "Done" << endl;
        cout << "Saving decrypted file...";
        fout.open("..\\..\\decrypted.obj");
        fout << recovered;
        fout.close();
        cout << "Done" << endl;

    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    return 0;
}