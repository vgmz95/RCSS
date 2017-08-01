#include "Fragmento.hpp"
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

Fragmento::Fragmento(std::string K, std::string C){
  this->K=K;
  this->C=C;
}

void Fragmento::obtieneHash(std::string nombreArchivo, int indice){
  CryptoPP::SHA256 sha256;
  CryptoPP::SecByteBlock digesto (NULL, CryptoPP::SHA256::DIGESTSIZE);
  //Hash(K,C)
  sha256.Restart();
  acumulaHashArchivo(sha256,K);
  acumulaHashArchivo(sha256,C);
  sha256.Final(digesto);
  //Ver hash
  std::string digesto_string;
  CryptoPP::ArraySource as(digesto,digesto.size(),true, //
    new CryptoPP::HexEncoder(
      new CryptoPP::StringSink(digesto_string)
    )
  );
  //Imprime hash
  std::cout <<"Hash "<<indice <<":"<<digesto_string << '\n';

}

void Fragmento::acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombreArchivo){
  CryptoPP::SecByteBlock buffer(NULL,64);
  std::FILE* f = std::fopen(nombreArchivo.c_str(), "r");
	int leido=0;
	do{
		std::memset(buffer.data(),'\0',buffer.size());
		leido=std::fread(buffer.data(), sizeof(byte), buffer.size(), f);
		sha256.Update(buffer.data(),leido);
	}while(leido!=0);
  std::fclose(f);

}
