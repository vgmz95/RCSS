all: Share Recover
	
Share: Archivo.cpp Hash.cpp ServidorSsh.cpp Share.cpp
	g++ -std=c++0x -g2 -O2 -Wall -Wextra -Wno-unused "Share.cpp" 	"Llave.cpp" "Archivo.cpp" "Hash.cpp" "Fragmento.cpp" "ServidorSsh.cpp" "./cryptopp/libcryptopp.a" -o "Share" 
	
Recover: Archivo.cpp Hash.cpp ServidorSsh.cpp Recover.cpp 
	g++ -std=c++0x -g2 -O2 -Wall -Wextra -Wno-unused "Recover.cpp"	"Llave.cpp" "Archivo.cpp" "Hash.cpp" "Fragmento.cpp" "ServidorSsh.cpp" "./cryptopp/libcryptopp.a" -o "Recover"

clean:
	rm Recover Share
