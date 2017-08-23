#include "Fragmento.hpp"
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include "ezpwd/rs"

Fragmento::Fragmento(std::string K, std::string C, std::vector<std::string> S, int indice) {
    this->K_nombre_archivo = K;
    this->C_nombre_archivo = C;
    this->S_nombre_fragmentos_ECC = S;
    this->ok = false;
    this->indice = indice;
}

std::ostream& operator<<(std::ostream& os, const Fragmento& obj) {
    // Write obj to stream
    os << "Fragmento número " << obj.indice << std::endl;
    os << "K:" << obj.K_nombre_archivo << ",\nC:" << obj.C_nombre_archivo << ",\nS: {" << std::endl;
    for (auto const& s : obj.S_nombre_fragmentos_ECC) {
        os << s << "," << std::endl;
    }
    os << "}" << std::endl;
    return os;
}

std::vector<std::string> Fragmento::getS() const {
    return S_nombre_fragmentos_ECC;
}

std::string Fragmento::getC() const {
    return C_nombre_archivo;
}

std::string Fragmento::getK() const {
    return K_nombre_archivo;
}

void Fragmento::recuperar() {
    ok = true;
}

bool Fragmento::isOk() const {
    return ok;
}

int Fragmento::getIndice() const {
    return indice;
}
