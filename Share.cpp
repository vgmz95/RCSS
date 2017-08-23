#include "Archivo.hpp"
#include "Llave.hpp"
#include "Hash.h"
#include "Fragmento.hpp"
#include <cryptopp/aes.h>
#include <string>

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
        std::cout << "Archivo a procesar: " << nombre_archivo << " umbral: " << umbral << "," << numero_shares << std::endl;
    } catch (std::exception& e) {
        std::cerr << "Error al parsear los argumentos: " << e.what() << std::endl;
        return -1;
    }

    Archivo archivo(nombre_archivo);
    Llave llave(nombre_archivo);
    llave.generar(); //Generación aleatoria de la llave
    archivo.cifrar(llave, iv); //Cifrado del archivo

    std::cout << "Share PSS..." << std::flush;
    std::vector <std::string> K = llave.sharePSS(umbral, numero_shares); //Share PSS de la llave
    std::cout << "OK" << std::endl;

    std::cout << "Share IDA..." << std::flush;
    std::vector <std::string> C = archivo.shareIDA(umbral, numero_shares); //Share IDA del archivo
    std::cout << "OK" << std::endl;

    std::cout << "Share ECC..." << std::flush;
    std::vector <std::vector < std::string>> S;
    S.reserve(numero_shares);
    for (unsigned int i = 0; i < numero_shares; i++) {
        Hash h = Hash(i);
        h.calculaHash(K[i], C[i]);
        S.push_back(h.shareECC(umbral, numero_shares, nombre_archivo));
    }
    std::cout << "OK" << std::endl;

    std::vector <Fragmento> fragmentos;
    fragmentos.reserve(numero_shares);
    std::cout << "\tInformación de los fragmentos" << std::endl;
    for (unsigned int i = 0; i < numero_shares; i++) {
        std::vector<std::string> S_temp;
        for (unsigned int j = 0; j < numero_shares; j++) {
            S_temp.push_back(S[j][i]);
        }
        Fragmento fragmento(K[i], C[i], S_temp, i);
        std::cout << fragmento << std::endl;
        fragmentos.push_back(fragmento);
    }

    //std::remove(nombre_archivo.c_str()); //Se borra el archivo original una vez terminado el proceso de share
    return 0;
}
