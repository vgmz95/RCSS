#Cryptopp
0)descomprimir la biblioteca
1)compilar biblioteca cryptopp
cd cryptopp
make clean
make

#compilar proyecto principal
cd RCSS
make 

#Compilar programas borrar renombrar
cd GestionArchivosCarpetas
make

#SSH
https://help.ubuntu.com/lts/serverguide/openssh-server.html
Secciones: Instalación y Claves SSH
Se debe de configurar de tal forma que las computadoras tengan su propia llave rsa y la llave de las demás maquinas. (comando ssh-copy-id username@remotehost)

#Ejecutar 
./Share nombre_archivo umbral numero_shares carpeta_destino archivo_servidores

Ejemplo
./Share archivo.txt 3 6 /carpetadestino/ejemplo servidores.txt
