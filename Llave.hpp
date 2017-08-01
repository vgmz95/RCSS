#ifndef LLAVE_H_
#define LLAVE_H_
#include "drbg.h"

class Llave{
	private:
		CryptoPP::SecByteBlock llave;
		std::string llaveCadena="";
		CryptoPP::Hash_DRBG<CryptoPP::SHA256, 128/8, 440/8> *drbg;
		CryptoPP::SecByteBlock generaEntropia();

	public:
		Llave();
		~Llave();
		void generar();
		CryptoPP::SecByteBlock obtieneLlave();
		std::vector <std::string> sharePSS(int umbral, int numeroShares, std::string nombreArchivo);
		void recoverPSS(int umbral, int numeroShares, std::vector <std::string> nombresArchivosPSS);
};

#endif
