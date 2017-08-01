all: Share Recover

Share: Share.cpp Archivo.cpp Llave.cpp Fragmento.cpp
	g++ -o "Share" "Share.cpp" "./Llave.cpp" "./Archivo.cpp" "./Fragmento.cpp" -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -lcryptopp -std=c++11

Recover: Recover.cpp Archivo.cpp Llave.cpp Fragmento.cpp
	g++ -o "Recover" "Recover.cpp" "./Llave.cpp" "./Archivo.cpp" "./Fragmento.cpp" -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -lcryptopp -std=c++11

clean:
	rm Recover
	rm Share
