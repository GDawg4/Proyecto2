all: bruteforce bruteforce2

bruteforce: bruteforce.cpp
	mpic++ -o bruteforce bruteforce.cpp -lcryptopp

bruteforce2: bruteforce2.cpp
	mpic++ -o bruteforce2 bruteforce2.cpp -lcryptopp
