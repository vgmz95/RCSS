#include "Llave.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>//Cifrador por bloques AES
#include <cryptopp/ida.h>//IDA y Shamir
#include <cryptopp/files.h> //Archivos
#include <cryptopp/filters.h> //
#include <cryptopp/hex.h> //quitar los HEX
#include "drbg.h"

Llave::Llave(){
	llave=CryptoPP::SecByteBlock(NULL,CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::SecByteBlock entropy=generaEntropia();//Inicializacion de la semilla (entropia)
	drbg=new CryptoPP::Hash_DRBG<CryptoPP::SHA256, 128/8, 440/8> (entropy, 32, entropy+32, 16); //Generador NIST Hash_DRBG, tiene como semilla la entropia generada anteriormente
}

Llave::~Llave(){
	delete drbg;	
}

CryptoPP::SecByteBlock Llave::obtieneLlave(){
	return llave;
}

CryptoPP::SecByteBlock Llave::generaEntropia(){//Función que se manda a llamar cada vez que se necesita añadir entropia al generador del NIST
	CryptoPP::SecByteBlock entropy(NULL,48); //Bloque donde se almacena la entropia
	OS_GenerateRandomBlock(true,entropy,entropy.size());
	return entropy;
}

void Llave::generar(){//Función que genera una llave aleatoria para el cifrador AES
	//CryptoPP::SecByteBlock entropy=generaEntropia(); //Se genera más entropia para el generador del NIST
	//drbg->IncorporateEntropy(entropy,entropy.size());//Se añade
	drbg->GenerateBlock(llave,llave.size());//Se genera una llave aleatoria
	llaveCadena.clear();
	CryptoPP::ArraySource(llave, llave.size(), true,
		new CryptoPP::StringSink(llaveCadena)
	);
	/////////////////
	std::string encoded="";
	encoded.clear();
	CryptoPP::StringSource ss( llaveCadena,true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))); // StringSource
	std::cout<<"Key:"<<encoded<<std::endl;
}

std::vector <std::string> Llave::sharePSS(int umbral, int numeroShares, std::string nombreArchivo){
	nombreArchivo+=".K"; ///////////Nombre base de los archivos de la llave. Se le añade al nombre del usuario la letra 'K' para denotar que es K negrita

	if (numeroShares < 1 || numeroShares > 1000)
			throw CryptoPP::InvalidArgument("SecretShareFile: " + CryptoPP::IntToString(numeroShares) + " is not in range [1, 1000]");

	CryptoPP::ChannelSwitch *channelSwitch = NULL;
	CryptoPP::StringSource source(llaveCadena, false,
		new CryptoPP::SecretSharing(*drbg, umbral, numeroShares,
			channelSwitch = new CryptoPP::ChannelSwitch)
	);

	std::vector <std::string> nombresArchivosPSS; //Vector donde se almacenan los nombres de los archivos generados

	CryptoPP::vector_member_ptrs<CryptoPP::FileSink> fileSinks(numeroShares);
	std::string channel;
	for (int i=0; i<numeroShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new CryptoPP::FileSink((nombreArchivo+extension).c_str()));
		nombresArchivosPSS.push_back(nombreArchivo+extension);//Se añade el nombre archivo al vector
		channel = CryptoPP::WordToString<CryptoPP::word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], CryptoPP::DEFAULT_CHANNEL);
	}

	source.PumpAll();
	return nombresArchivosPSS;
}



void Llave::recoverPSS(int umbral, int numeroShares, std::vector <std::string> nombresArchivosPSS){
	if (umbral < 1 || umbral > 1000)
		throw CryptoPP::InvalidArgument("SecretRecoverFile: " + CryptoPP::IntToString(umbral) + " is not in range [1, 1000]");

	CryptoPP::SecretRecovery recovery(umbral,
		new CryptoPP::ArraySink(llave,llave.size())
	);

	CryptoPP::vector_member_ptrs<CryptoPP::FileSource> fileSources(umbral);
	CryptoPP::SecByteBlock channel(4);
	int i;
	for (i=0; i<umbral; i++){
		fileSources[i].reset(new CryptoPP::FileSource(nombresArchivosPSS[i].c_str(), false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<umbral; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<umbral; i++)
		fileSources[i]->PumpAll();

}
