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

SecByteBlock SecretRecover(int threshold, SecByteBlock llave, string inFilenames[]);//Recover PSS
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
		SecByteBlock llave(NULL,AES::DEFAULT_KEYLENGTH);//NULL para inicializar en 0's
		
		//Vector de inicializacion IV
		SecByteBlock iv(NULL,AES::DEFAULT_KEYLENGTH);//NULL para inicializar en 0's
		
		//For para generar los nombres de los archivos de la llave K con base en el nombre del archivo a recuperar
		string *archivosK=new string[numeroShares];
		for(int i=0;i<numeroShares;i++){
			char extension[5] = ".000";
			extension[1]='0'+byte(i/100);
			extension[2]='0'+byte((i/10)%10);
			extension[3]='0'+byte(i%10);
			archivosK[i]=archivo+".K"+extension;
		}
		
		//For para generar los nombres de los archivos del cifrado C con base en el nombre del archivo a recuperar
		string *archivosC=new string[numeroShares];
		for(int i=0;i<numeroShares;i++){
			char extension[5] = ".000";
			extension[1]='0'+byte(i/100);
			extension[2]='0'+byte((i/10)%10);
			extension[3]='0'+byte(i%10);
			archivosC[i]=archivo+".C"+extension;
		}
		
		//Recover PSS K_negrita->k
		llave=SecretRecover(umbral,llave,archivosK);
		
		//Recover IDA C_negrita->c
		string archivoCifrado(archivo+".c"); 
		InformationRecoverFile(umbral,archivoCifrado.c_str(),archivosC);
		
		//Decrypt_k_(C) 
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(llave,llave.size(),iv);
		FileSource s(archivoCifrado.c_str(),true,
			new StreamTransformationFilter(d,
				new FileSink (("RECUPERADO_"+archivo).c_str(),true)
			) 
		);
		
		remove(archivoCifrado.c_str());//Borra el archivo cifrado C
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

SecByteBlock SecretRecover(int threshold, SecByteBlock llave, string inFilenames[]){	
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	SecretRecovery recovery(threshold, 
		new ArraySink(llave,llave.size())
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

	return llave;
}
