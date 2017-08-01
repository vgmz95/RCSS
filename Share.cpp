#include "Llave.hpp"
#include "Archivo.hpp"
#include "Fragmento.hpp"

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
	llave.generar(); //Generación aleatoria de la llave
	archivo.cifrar(llave,iv); //Cifrado del archivo

	std::vector <std::string> K;//K negrita
	K=llave.sharePSS(umbral,numeroShares,archivo.getNombreArchivo());//Share PSS de la llave

	std::vector <std::string> C;//C negrita
	C=archivo.shareIDA(umbral,numeroShares);//Share IDA del archivo

	std::vector <Fragmento> fragmentos;
	for(int i=0;i<numeroShares;i++){
		fragmentos.push_back(Fragmento(K[i],C[i]));
	}

	for(unsigned int i=0;i<fragmentos.size();i++){
		fragmentos[i].obtieneHash(archivo.getNombreArchivo(),i);
	}

	std::remove(nombreArchivo.c_str()); //Se borra el archivo original una vez terminado el proceso de share
	return 0;
}
