# mon-rssi-mac
a small C program written purely on libpcap to monitor 802.11 wifi probes (ssid, MAC addresses and RSSI values).

## Usage
```bash
make
./mon-rssi-mac <interface name>

# for example
./mon-rssi-mac wlan0
```

Tested on OSX and kali linux
