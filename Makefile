default: program

FILE=mon-rssi-mac

program: $(FILE).c Makefile
	gcc $(FILE).c -o $(FILE) -lpcap
