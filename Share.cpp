
#include "Archivo.hpp"
#include "Llave.hpp"
#include "Hash.h"
#include "Fragmento.hpp"
#include <cryptopp/aes.h>

int main(int argc, char *argv[]) {
    //Vector de inicializacion IV  *Debe de ser público*
    CryptoPP::SecByteBlock iv(NULL, CryptoPP::AES::BLOCKSIZE); //NULL para inicializar en 0's
    std::string nombre_archivo = "";
    unsigned int umbral;
    unsigned int numero_shares;

    try {//Parseo de argumentos
        nombre_archivo = std::string(argv[1]); //Archivo
        umbral = std::stoul(std::string(argv[2]));
        numero_shares = std::stoul(std::string(argv[3]));
    } catch (std::exception& e) {
        std::cerr << "Error al parsear los argumentos: " << e.what() << std::endl;
        return -1;
    }

    Archivo archivo(nombre_archivo);
    Llave llave(nombre_archivo);
    llave.generar(); //Generación aleatoria de la llave
    archivo.cifrar(llave, iv); //Cifrado del archivo

    std::vector <std::string> K = llave.sharePSS(umbral, numero_shares); //Share PSS de la llave
    std::vector <std::string> C = archivo.shareIDA(umbral, numero_shares); //Share IDA del archivo
    std::vector <Hash> H;
    for (unsigned int i = 0; i < numero_shares; i++) {
        Hash h = Hash(K[i], C[i], i);
        H.push_back(h);
        H[i].calculaHash();
        H[i].shareECC(numero_shares, nombre_archivo);
    }

    std::vector <Fragmento> fragmentos;
    for (unsigned int i = 0; i < numero_shares; i++) {
        std::vector<std::string> S;
        for (unsigned int j = 0; j < numero_shares; j++) {
            S.push_back(H[j].getSNombreFragmentosECC()[i]);
        }
        fragmentos.push_back(Fragmento(K[i], C[i], S));
    }

    std::remove(nombre_archivo.c_str()); //Se borra el archivo original una vez terminado el proceso de share
    return 0;
}
