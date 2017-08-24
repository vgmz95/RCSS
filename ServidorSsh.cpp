/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ServidorSsh.cpp
 * Author: victor
 * 
 * Created on 22 de agosto de 2017, 06:17 PM
 */

#include "ServidorSsh.hpp"
#include <string>
#include <iostream>

ServidorSsh::ServidorSsh(std::string usuario, std::string host) {
    this->host = host;
    this->usuario = usuario;
}

ServidorSsh::ServidorSsh(const ServidorSsh& orig) {
    this->host = orig.host;
    this->usuario = orig.usuario;
}

ServidorSsh::~ServidorSsh() {
    this->host.clear();
    this->usuario.clear();
}

bool ServidorSsh::copiaHome(std::vector<std::string> nombreArchivos, std::string carpetaDestino, std::string nombreArchivo) {
    std::string mkdir = "ssh " + usuario + "@" + host + " 'mkdir -p /home/" + usuario + "/RCSS/" + carpetaDestino + "/" + nombreArchivo + "'";
    std::cout << mkdir << std::endl;
    int resultado = std::system(mkdir.c_str());
    for (auto &nombreArchivoDistribuir : nombreArchivos) {
        std::string comando = "scp " + nombreArchivoDistribuir + " " + usuario + "@" + host + ":" + "/home/" + usuario + "/RCSS/" + carpetaDestino + "/" + nombreArchivo + "/" + nombreArchivoDistribuir;
        std::cout << comando << std::endl;
        resultado = std::system(comando.c_str());
        if (resultado > 0) {
            return false;
        }
    }
    return true;
}

bool ServidorSsh::recuperaHome(std::vector<std::string> nombreArchivos, std::string carpetaOrigen, std::string nombreArchivo) {
    //scp usuario@dominio.com:/home/usuario/archivo.txt Documentos
    for (auto &nombreArchivoRecuperar : nombreArchivos) {
        std::string comando = "scp " + usuario + "@" + host + ":" + "/home/" + usuario + "/RCSS/" + carpetaOrigen + "/" + nombreArchivo + "/" + nombreArchivoRecuperar + " ./";
        std::cout << comando << std::endl;
        int resultado = std::system(comando.c_str());
        if (resultado > 0) {
            return false;
        }
    }
    return true;
}
