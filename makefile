all: Recover Share

Recover: Recover.cpp
	g++ -o "Recover" "Recover.cpp" -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -lcryptopp  -std=c++11 
	
Share: Share.cpp
	g++ -o "Share" "Share.cpp" -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -lcryptopp  -std=c++11
	
clean:
	rm Recover
	rm Share
