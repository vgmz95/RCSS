#include "Llave.hpp"
#include "Archivo.hpp"
#include "Fragmento.hpp"
#include "Hash.h"
#include <cryptopp/aes.h>
#include <sstream>
#include <iomanip>

std::vector <std::string> generaNombresArchivos(std::string nombreArchivo, unsigned int numeroShares, std::string extension_intermedia);
std::vector <std::vector<std::string>> generaNombresArchivosECC(std::string nombre_archivo, unsigned int numero_shares, std::string extension_intermedia);
void parseaArgumentos(char** argv, std::string& nombre_archivo, int& umbral, int& numero_shares);

std::vector < std::string> obtieneSCorrespondiente(int numero_fragmento, std::vector <std::vector < std::string>> S) {
    std::vector < std::string> S_correspondiente;
    for (unsigned int i = 0; i < S.size(); i++) {
        S_correspondiente.push_back(S[i][numero_fragmento]);
    }
    return S_correspondiente;
}

int main(int argc, char *argv[]) {
    //Vector de inicializacion IV  *Debe de ser público*
    CryptoPP::SecByteBlock iv(NULL, CryptoPP::AES::BLOCKSIZE); //NULL para inicializar en 0's
    std::string nombre_archivo = "";
    int umbral;
    int numero_shares;
    //Parseo de argumentos
    try {
        parseaArgumentos(argv, nombre_archivo, umbral, numero_shares);
    } catch (std::exception& e) {
        std::cerr << "Error al parsear los argumentos: " << e.what() << std::endl;
        return -1;
    }
    //Paso 1 RCSS
    //Obtencion de los nombres y las referencias 
    std::vector <std::string> K = generaNombresArchivos(nombre_archivo, numero_shares, std::string("K"));
    std::vector <std::string> C = generaNombresArchivos(nombre_archivo, numero_shares, std::string("C"));
    std::vector <std::vector < std::string>> S = generaNombresArchivosECC(nombre_archivo, numero_shares, std::string("S"));
    std::vector <Fragmento> fragmentos;
    for (int i = 0; i < numero_shares; i++) {
        fragmentos.push_back(Fragmento(K[i], C[i], S[i]));
    }

    //Paso 2 RCSS
    std::vector <Hash> H;
    for (unsigned int i = 0; i < fragmentos.size(); i++) {
        H.push_back(Hash(obtieneSCorrespondiente(i, S)));
        H[i].recoverECC();
    }

    //Paso 3 RCSS
    std::vector <int> indicesOK;
    for (unsigned int i = 0; i < fragmentos.size(); i++) {
        Hash hash(K[i], C[i], i);
        hash.calculaHash();
        if (hash == H[i]) {
            indicesOK.push_back(i);
            std::cout << "El fragmento número " << std::to_string(i) << " esta correcto" << std::endl;
        } else {
            std::cout << "El fragmento número " << std::to_string(i) << " esta corrupto" << std::endl;
        }
    }
    //Eliminar de K y C los que no estan OK

    //Paso 4,5,6 RCSS
    Archivo archivo(nombre_archivo, C);
    Llave llave(nombre_archivo, K);
    llave.recoverPSS(umbral, numero_shares); //Recuperacion llave
    archivo.recoverIDA(umbral, numero_shares); //Recuperacion archivo
    archivo.descifrar(llave, iv); //Descifrado
    return 0;
}

void parseaArgumentos(char** argv, std::string& nombre_archivo, int& umbral, int& numero_shares) {
    nombre_archivo = std::string(argv[1]); //Archivo
    umbral = std::stoi(std::string(argv[2]));
    numero_shares = std::stoi(std::string(argv[3]));
}

std::vector <std::string> generaNombresArchivos(std::string nombre_archivo, unsigned int numero_shares, std::string extension_intermedia) {
    std::vector <std::string> nombres;
    std::string extension;
    std::stringstream str_stream;
    std::string nombre_archivo_tmp;
    for (unsigned int i = 0; i < numero_shares; i++) {
        str_stream << std::setw(3) << std::setfill('0') << i; //Genera la cadena 000,001,002
        extension = "." + extension_intermedia + "." + str_stream.str();
        nombre_archivo_tmp = nombre_archivo + extension;
        nombres.push_back(nombre_archivo_tmp);
        str_stream.str("");
        str_stream.clear();
        extension.clear();
        nombre_archivo_tmp.clear();
    }
    return nombres;
}

std::vector <std::vector < std::string>> generaNombresArchivosECC(std::string nombre_archivo, unsigned int numero_shares, std::string extension_intermedia) {
    std::vector <std::vector < std::string>> nombres;
    std::vector < std::string> nombres_temp;
    std::stringstream str_stream;
    std::string nombre_archivo_tmp;
    for (unsigned int i = 0; i < numero_shares; i++) {
        for (unsigned int j = 0; j < numero_shares; j++) {
            str_stream << std::setw(3) << std::setfill('0') << i; //Genera la cadena 000,001,002
            nombre_archivo_tmp = nombre_archivo + "." + extension_intermedia + "." + str_stream.str();
            str_stream.str("");
            str_stream.clear();
            str_stream << std::setw(3) << std::setfill('0') << j;
            nombre_archivo_tmp += "." + str_stream.str();
            //std::cout << nombre_archivo_tmp << std::endl;
            nombres_temp.push_back(nombre_archivo_tmp);
            str_stream.str("");
            str_stream.clear();
            nombre_archivo_tmp.clear();
        }
        nombres.push_back(nombres_temp);
    }
    return nombres;
}

