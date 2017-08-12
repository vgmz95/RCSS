#ifndef HASH_H
#define HASH_H
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

class Hash {
public:
    Hash(std::string, std::string, unsigned int);
    Hash(std::vector<std::string> S_nombre_fragmentos_ECC);
    virtual ~Hash();
    void calculaHash();
    void shareECC(unsigned int, std::string);
    void recoverECC();
    
    bool operator==(const Hash& right) const {
        return this->H_data_string==right.H_data_string;
    }


    std::vector<std::string> getSNombreFragmentosECC() const {
        return S_nombre_fragmentos_ECC;
    }

private:
    std::string C_nombre_archivo;
    std::string K_nombre_archivo;
    CryptoPP::SHA256 sha256;
    CryptoPP::SecByteBlock H_data;
    std::string H_data_string;
    std::vector<std::string> S_data;
    std::vector<std::string> S_nombre_fragmentos_ECC;
    unsigned int indice;
    void acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombre_archivo);

};

#endif /* HASH_H */

