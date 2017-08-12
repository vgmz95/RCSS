#include "Fragmento.hpp"
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include "ezpwd/rs"

Fragmento::Fragmento(std::string K, std::string C, std::vector<std::string> S){
  this->K_nombre_archivo=K;
  this->C_nombre_archivo=C;
  this->S_nombre_fragmentos_ECC=S;
  this->ok=true;
}