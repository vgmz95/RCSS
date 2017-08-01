#ifndef FRAGMENTO_H_
#define FRAGMENTO_H_
#include <string>
#include <iostream>
#include <cryptopp/sha.h>
class Fragmento{
private:
  std::string K;
  std::string C;
  std::string H;
  bool ok;
  std::vector<std::string> S;

  void acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombreArchivo);
public:
  Fragmento(std::string K, std::string C);
  void obtieneHash(std::string nombreArchivo, int indice);
  void shareECC(void);
  void recoverECC(void);
};

#endif
