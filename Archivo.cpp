#include "Archivo.hpp"
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h> //Archivos
#include <cryptopp/ida.h>//IDA y Shamir
#include <cstdio> //para borrar archivo (std::remove)

Archivo::Archivo(std::string nombreArchivo){
	this->nombreArchivo=nombreArchivo;
}

std::string Archivo::getNombreArchivo(){
	return nombreArchivo;
}

void Archivo::cifrar(Llave &llave, CryptoPP::SecByteBlock iv){
	nombreArchivoCifrado=std::string(nombreArchivo+".C"); /////*********************Nombre base que se le asigna al archivo una vez cifrado**************///////
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cifrado; //Objeto para el cifrado usando AES modo CBC
	cifrado.SetKeyWithIV(llave.obtieneLlave(),llave.obtieneLlave().size(), iv);//Se asigna la llave y el IV
	//Se cifra el archivo
	CryptoPP::FileSource s(nombreArchivo.c_str(),true,
	new CryptoPP::StreamTransformationFilter(cifrado,
		new CryptoPP::FileSink (nombreArchivoCifrado.c_str(),true)
	)
);
}

void Archivo::descifrar(Llave &llave, CryptoPP::SecByteBlock iv){
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
	d.SetKeyWithIV(llave.obtieneLlave(),llave.obtieneLlave().size(),iv);
	CryptoPP::FileSource s(nombreArchivoCifrado.c_str(),true,
		new CryptoPP::StreamTransformationFilter(d,
			new CryptoPP::FileSink (nombreArchivo.c_str(),true) /////*********************Nombre que se le asigna al archivo una vez recuperado en claro**************///////
		)
	);
	std::remove(nombreArchivoCifrado.c_str());//Borra el archivo cifrado C
}

std::vector <std::string> Archivo::shareIDA(int umbral, int numeroShares){
	if (umbral < 1 || umbral > 1000)
	throw CryptoPP::InvalidArgument("InformationDisperseFile: " + CryptoPP::IntToString(numeroShares) + " is not in range [1, 1000]");

	CryptoPP::ChannelSwitch *channelSwitch = NULL;
	CryptoPP::FileSource source(nombreArchivoCifrado.c_str(), false,
	new CryptoPP::InformationDispersal(umbral, numeroShares,
		channelSwitch = new CryptoPP::ChannelSwitch
		)
	);

	CryptoPP::vector_member_ptrs<CryptoPP::FileSink> fileSinks(numeroShares);
	std::string channel;
	std::vector <std::string> nombresArchivosIDA; //Vector donde se almacenan los nombres de los archivos generados
	for (int i=0; i<numeroShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		fileSinks[i].reset(new CryptoPP::FileSink((nombreArchivoCifrado+extension).c_str()));
		nombresArchivosIDA.push_back(nombreArchivoCifrado+extension);//Se añade el nombre archivo al vector
		channel = CryptoPP::WordToString<CryptoPP::word32>(i);
		fileSinks[i]->Put((const byte *)channel.data(), 4);
		channelSwitch->AddRoute(channel, *fileSinks[i], CryptoPP::DEFAULT_CHANNEL);
	}
	source.PumpAll();
	std::remove(nombreArchivoCifrado.c_str());//Se borra el archivo cifrado original, una ves que ya se crearon sus shares
	return nombresArchivosIDA;
}

void Archivo::recoverIDA(int umbral, int numeroShares,  std::vector <std::string> nombresArchivosIDA){
	if (umbral < 1 || umbral > 1000)
	throw CryptoPP::InvalidArgument("InformationRecoverFile: " + CryptoPP::IntToString(umbral) + " is not in range [1, 1000]");
	nombreArchivoCifrado=nombreArchivo+".C"; /////******************************Nombre que se le asigna al archivo CIFRADO una vez recuperado********************///////.
	CryptoPP::InformationRecovery recovery(umbral, new CryptoPP::FileSink(nombreArchivoCifrado.c_str()));
	CryptoPP::vector_member_ptrs<CryptoPP::FileSource> fileSources(umbral);
	CryptoPP::SecByteBlock channel(4);
	int i;
	for (i=0; i<umbral; i++){
		fileSources[i].reset(new CryptoPP::FileSource(nombresArchivosIDA[i].c_str(), false));
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
