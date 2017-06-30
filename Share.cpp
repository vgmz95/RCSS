//C++
#include <iostream>
#include <string>
#include <cstdlib>

//Crypto++
#include <cryptopp/cryptlib.h> //Biblioteca principal
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/randpool.h>
#include <cryptopp/channels.h>

//IDA y Shamir
#include <cryptopp/ida.h>

//Espacio de nombres
using namespace std;
using namespace CryptoPP;

void SecretShare(int threshold, int nShares, byte llave[], const char *seed, string filename); //Share PSS- El argumento 'seed' es para añadir aleatoridad al algoritmo
void InformationDisperseFile(int threshold, int nShares, string filename);//Share IDA

int main(int argc, char *argv[]){
	//**Falta generar las cosas de forma aleatoria**
	string archivo;
	int umbral;
	int numeroShares;
		
	try {
		archivo=string(argv[1]);//Archivo
		umbral=stoi(string(argv[2]));
		numeroShares=stoi(string(argv[3]));
	}catch(exception& e){
		cerr<<"Error al parsear los argumentos: "<<e.what()<<endl;
		return -1;
	}
	
	//Llave k
	array<byte,AES::DEFAULT_KEYLENGTH> llave;
	memset(llave.data(),'\0',llave.size());//Limpieza de la llave	
	
	//Vector de inicializacion IV  *Checar como se va a almacenar eso :v*
	array<byte,AES::BLOCKSIZE> iv;
	memset(iv.data(),'\0',iv.size());//Limpieza del IV
	
	 try {
		//Cifrado del archivo
		string archivoCifrado(archivo+".C"); 
		CBC_Mode<AES>::Encryption cifrado; //Objeto para el cifrado usando AES modo CBC
		cifrado.SetKeyWithIV(llave.data(),llave.size(), iv.data());//Se asigna la llave y el IV
		FileSource s(archivo.c_str(),true,
			new StreamTransformationFilter(cifrado,
				new FileSink (archivoCifrado.c_str(),true)
			)       
		);//Se cifra el archivo
		
		//PSS
		string archivoLlave(archivo+".K"); //Nombre del archivo de salida del proceso de Share PSS 
		SecretShare(umbral,numeroShares,llave.data(),"",archivoLlave);//Share PSS k->K_negrita 
		//IDA
		InformationDisperseFile(umbral,numeroShares,archivoCifrado);//Share IDA c->C_negrita	
		remove(archivoCifrado.c_str());//Borra el archivo cifrado
	}catch(exception& e){
		cerr<<"Error durante el proceso del archivo: "<<e.what()<<endl;
		return -1;
	}
	
	return 0;
}

void SecretShare(int threshold, int nShares, byte llave[], const char *seed, string filename){
	if (nShares < 1 || nShares > 1000)
		throw InvalidArgument("SecretShareFile: " + IntToString(nShares) + " is not in range [1, 1000]");	
	
	RandomPool rng;
	rng.IncorporateEntropy((byte *)seed, strlen(seed));

	ChannelSwitch *channelSwitch = NULL;
	ArraySource source(llave, false, 
		new SecretSharing(rng, threshold, nShares, 
			channelSwitch = new ChannelSwitch)
	);
	
	vector_member_ptrs<FileSink> fileSinks(nShares);
	string channel;
	for (int i=0; i<nShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((filename+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
	}

	source.PumpAll();	
}

void InformationDisperseFile(int threshold, int nShares, string filename){
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("InformationDisperseFile: " + IntToString(nShares) + " is not in range [1, 1000]");

	ChannelSwitch *channelSwitch = NULL;
	FileSource source(filename.c_str(), false, new InformationDispersal(threshold, nShares, channelSwitch = new ChannelSwitch));

	vector_member_ptrs<FileSink> fileSinks(nShares);
	string channel;
	for (int i=0; i<nShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new FileSink((filename+extension).c_str()));

		channel = WordToString<word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
	}
	source.PumpAll();
}
