/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ServidorSsh.h
 * Author: victor
 *
 * Created on 22 de agosto de 2017, 06:17 PM
 */

#ifndef SERVIDORSSH_H
#define SERVIDORSSH_H
#include <string>
#include <vector>

class ServidorSsh {
public:
    ServidorSsh(std::string, std::string);
    bool copiaHome(std::vector<std::string>, std::string, std::string);
    bool recuperaHome(std::vector<std::string>, std::string, std::string);
    ServidorSsh(const ServidorSsh& orig);
    virtual ~ServidorSsh();
private:
    std::string host;
    std::string usuario;
};

#endif /* SERVIDORSSH_H */

