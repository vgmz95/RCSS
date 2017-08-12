#ifndef FRAGMENTO_H_
#define FRAGMENTO_H_
#include <string>
#include <iostream>
#include <cryptopp/sha.h>

class Fragmento {
public:
    Fragmento(std::string K, std::string C, std::vector<std::string> S);
    
private:
    std::string K_nombre_archivo;
    std::string C_nombre_archivo;
    std::vector<std::string> S_nombre_fragmentos_ECC;
    std::string H_data;
    std::vector<std::string> S_data;
    bool ok;

    void acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombreArchivo);


};



#endif
