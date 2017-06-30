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

void SecretRecover(int threshold, array<byte,AES::DEFAULT_KEYLENGTH> &llave, string inFilenames[]);//Recover PSS
void InformationRecoverFile(int threshold, string outFilename, string inFilenames[]);//Recover IDA

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
	
	try {
	
		//Llave k
		array<byte,AES::DEFAULT_KEYLENGTH> llave;
		memset(llave.data(),'\0',llave.size());//Limpieza de la llave	
		
		//Vector de inicializacion IV  *Checar como se va a almacenar eso :v*
		array<byte,AES::BLOCKSIZE> iv;
		memset(iv.data(),'\0',iv.size());//Limpieza del IV
		
		string *archivosK=new string[numeroShares];
		for(int i=0;i<numeroShares;i++){
			char extension[5] = ".000";
			extension[1]='0'+byte(i/100);
			extension[2]='0'+byte((i/10)%10);
			extension[3]='0'+byte(i%10);
			archivosK[i]=archivo+".K"+extension;
		}
		
		string *archivosC=new string[numeroShares];
		for(int i=0;i<numeroShares;i++){
			char extension[5] = ".000";
			extension[1]='0'+byte(i/100);
			extension[2]='0'+byte((i/10)%10);
			extension[3]='0'+byte(i%10);
			archivosC[i]=archivo+".C"+extension;
		}
		
		//Recover PSS K_negrita->k
		SecretRecover(umbral,llave,archivosK);
		
		//Recover IDA C_negrita->c
		string archivoCifrado(archivo+".c"); 
		InformationRecoverFile(umbral,archivoCifrado.c_str(),archivosC);
		
		//Decrypt_k_(C) 
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(llave.data(),llave.size(), iv.data());
		FileSource s(archivoCifrado.c_str(),true,
			new StreamTransformationFilter(d,
				new FileSink (("Recuperado_"+archivo).c_str(),true)
			) 
		);
		
		remove(archivoCifrado.c_str());//Borra el archivo cifrado		
		delete[] archivosC;
		delete[] archivosK;
		
	}catch(exception& e){
		cerr<<"Error durante el proceso del archivo: "<<e.what()<<endl;
		return -1;
	}
		
	return 0;	
}


void InformationRecoverFile(int threshold, string outFilename, string inFilenames[]){
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("InformationRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	InformationRecovery recovery(threshold, new FileSink(outFilename.c_str()));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++){
		fileSources[i].reset(new FileSource(inFilenames[i].c_str(), false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}

void SecretRecover(int threshold,array<byte,AES::DEFAULT_KEYLENGTH> &llave, string inFilenames[]){	
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	SecretRecovery recovery(threshold, 
		new ArraySink(llave.data(),llave.size())
	);

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++){
		fileSources[i].reset(new FileSource(inFilenames[i].c_str(), false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}
