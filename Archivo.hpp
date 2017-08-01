#ifndef ARCHIVO_H_
#define ARCHIVO_H_
#include "Llave.hpp"
#include <string>
#include <cryptopp/files.h> //Escritura en archivos
#include <cryptopp/aes.h>//Cifrador por bloques AES
#include <cryptopp/ccm.h>//Modo de operación CBC
#include <cryptopp/filters.h>

class Archivo{
	private:
	std::string nombreArchivo;
	std::string nombreArchivoCifrado;
	public:
	Archivo(std::string nombreArchivo);
	void cifrar(Llave &llave, CryptoPP::SecByteBlock iv);
	void descifrar(Llave &llave, CryptoPP::SecByteBlock iv);
	std::vector <std::string> shareIDA(int umbral, int numeroShares);
	void recoverIDA(int umbral, int numeroShares,  std::vector <std::string> nombresArchivosIDA);
	std::string getNombreArchivo();

};

#endif
