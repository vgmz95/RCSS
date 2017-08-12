#include "Hash.h"
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h> //
#include "ezpwd/rs"

Hash::Hash(std::string K_nombre_archivo, std::string C_nombre_archivo, unsigned int indice) {
    this->C_nombre_archivo = C_nombre_archivo;
    this->K_nombre_archivo = K_nombre_archivo;
    this->indice = indice;
    this->H_data = CryptoPP::SecByteBlock(NULL, CryptoPP::SHA256::DIGESTSIZE);
    this->H_data_string="";
}

Hash::Hash(std::vector<std::string> S_nombre_fragmentos_ECC) {
    this->S_nombre_fragmentos_ECC = S_nombre_fragmentos_ECC;
    this->H_data_string="";
}

Hash::~Hash() {
    this->C_nombre_archivo.clear();
    this->K_nombre_archivo.clear();
}

void Hash::calculaHash() {
    sha256.Restart();
    acumulaHashArchivo(sha256, K_nombre_archivo); //K
    acumulaHashArchivo(sha256, C_nombre_archivo); //C
    sha256.Final(H_data);
    CryptoPP::ArraySource as(H_data, H_data.size(), true,
            new CryptoPP::StringSink(H_data_string)
            );
    std::cout<<"Tamaño del hash:"<<std::to_string(H_data_string.length())<<std::endl;

}

void Hash::acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombre_archivo) {
    CryptoPP::SecByteBlock buffer(NULL, 64);
    std::FILE* f = std::fopen(nombre_archivo.c_str(), "r");
    int leido = 0;
    do {
        std::memset(buffer.data(), '\0', buffer.size());
        leido = std::fread(buffer.data(), sizeof (byte), buffer.size(), f);
        sha256.Update(buffer.data(), leido);
    } while (leido != 0);
    std::fclose(f);
}

void Hash::shareECC(unsigned int numero_shares, std::string nombre_archivo) {
    ezpwd::RS < 255, 255 - 64 > rs; //Reed-Solomon, 64 simbolos de paridad
    std::string paridad = "";
    rs.encode(H_data_string, paridad);
    std::cout<<"Tamaño paridad sola: "<<paridad.length()<<std::endl;
    unsigned int tamano = paridad.length();
    std::string subdivision = "";
    unsigned int x_0 = 0;
    unsigned int incremento = (tamano / numero_shares) - 1;
    unsigned int modulo = tamano % numero_shares;
    for (unsigned int i = 0; i < numero_shares; i++) {
        if (modulo != 0 && i == (numero_shares - 1)) {//Numero de shares no multiplo
            subdivision = paridad.substr(x_0);
        } else {
            subdivision = paridad.substr(x_0, incremento+1);
        }
        std::cout<<"S="<<H_data_string.length()<<","<< subdivision.length()<<std::endl;
        S_data.push_back(H_data_string + subdivision);
        x_0 += incremento + 1;
        subdivision.clear();
    }

    std::string nombre_archivo_temp;
    std::string indice_str;
    std::string i_str;
    std::stringstream str_stream;
    for (unsigned int i = 0; i < S_data.size(); i++) {
        str_stream << std::setw(3) << std::setfill('0') << i;
        i_str = str_stream.str();
        str_stream.str("");
        str_stream.clear();
        str_stream << std::setw(3) << std::setfill('0') << indice;
        indice_str = str_stream.str();
        str_stream.str("");
        str_stream.clear();
        nombre_archivo_temp = nombre_archivo + ".S." + indice_str + '.' + i_str;
        CryptoPP::StringSource ss(S_data[i], true,
                new CryptoPP::FileSink(nombre_archivo_temp.c_str(), true)
                );
        std::cout<<"Tamaño de la paridad y el hash juntos: "<<std::to_string(S_data[i].length())<<std::endl;
        S_nombre_fragmentos_ECC.push_back(nombre_archivo_temp);
        indice_str.clear();
        i_str.clear();
        nombre_archivo_temp.clear();
    }

}

void Hash::recoverECC() {
    std::string S_data_temp = "";
    for (unsigned int i = 0; i < S_nombre_fragmentos_ECC.size(); i++) {
        CryptoPP::FileSource fs(S_nombre_fragmentos_ECC[i].c_str(), true,
                new CryptoPP::StringSink(S_data_temp),
                true);
        S_data.push_back(S_data_temp);
        S_data_temp.clear();
    }

    std::string paridad = ""; //Recuperando la informacion de paridad
    for (unsigned int i = 0; i < S_data.size(); i++) {
        paridad += S_data[i].substr(32);
    }
    std::cout<<"Tamaño de la paridad:"<<paridad.length()<<std::endl;

    ezpwd::RS < 255, 255 - 64 > rs; //64 simbolos de paridad
    std::string encoded = S_data[0];
    std::string code = encoded.substr(0, 32) + paridad;
    rs.decode(code);
    H_data_string = code.substr(0, encoded.length() - rs.nroots());
}
