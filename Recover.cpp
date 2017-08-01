#include "Llave.hpp"
#include "Archivo.hpp"
#include "Fragmento.hpp"

std::vector <std::string> generaNombresArchivosIDA(std::string nombreArchivo, int numeroShares);
std::vector <std::string> generaNombresArchivosPSS(std::string nombreArchivo, int numeroShares);

int main(int argc, char *argv[]){
	//Vector de inicializacion IV  *Debe de ser público*
	CryptoPP::SecByteBlock iv(NULL,CryptoPP::AES::BLOCKSIZE);//NULL para inicializar en 0's
	std::string nombreArchivo="";
	int umbral;
	int numeroShares;
	//Parseo de argumentos
	try {
			nombreArchivo=std::string(argv[1]);//Archivo
			umbral=std::stoi(std::string(argv[2]));
			numeroShares=std::stoi(std::string(argv[3]));
	}catch(std::exception& e){
			std::cerr<<"Error al parsear los argumentos: "<<e.what()<<std::endl;
			return -1;
	}

	Archivo archivo(nombreArchivo);
	Llave llave;
	std::vector <std::string> K=generaNombresArchivosPSS(nombreArchivo,numeroShares);
	std::vector <std::string> C=generaNombresArchivosIDA(nombreArchivo,numeroShares);
	std::vector <Fragmento> fragmentos;
	for(int i=0;i<numeroShares;i++){
		fragmentos.push_back(Fragmento(K[i],C[i]));
	}

	for(unsigned int i=0;i<fragmentos.size();i++){
		fragmentos[i].obtieneHash(archivo.getNombreArchivo(),i);
	}

	llave.recoverPSS(umbral, numeroShares, K);//Recuperacion llave
	archivo.recoverIDA(umbral, numeroShares, C);//Recuperacion archivo
	archivo.descifrar(llave,iv);//Descifrado
	return 0;
}


std::vector <std::string> generaNombresArchivosIDA(std::string nombreArchivo, int numeroShares){
	std::vector <std::string> nombresArchivosIDA;
	nombreArchivo+=".C";
	for (int i=0; i<numeroShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		nombresArchivosIDA.push_back(nombreArchivo+extension);//Se añade el nombre archivo al vector
	}
	return nombresArchivosIDA;
}

std::vector <std::string> generaNombresArchivosPSS(std::string nombreArchivo, int numeroShares){
	std::vector <std::string> nombresArchivosPSS;
	nombreArchivo+=".K";
	for (int i=0; i<numeroShares; i++){
		char extension[5] = ".000";
		extension[1]='0'+byte(i/100);
		extension[2]='0'+byte((i/10)%10);
		extension[3]='0'+byte(i%10);
		nombresArchivosPSS.push_back(nombreArchivo+extension);//Se añade el nombre archivo al vector
	}
	return nombresArchivosPSS;
}
