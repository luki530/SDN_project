# SDN_project

## Uruchomienie

1) Pobierz laboratorium z przedmiotu SDN
2) Podmień pliki zawierające się w tym repozytorium
3) Uruchom scenariusz


### Zestawienie topologii
```
sudo mn --topo single,3  --controller=remote,ip=127.0.0.1,port=6653
```

### Uruchomienie serwera HTTP
```shell
python3 -m http.server 80
```

### Uruchomienie nmapa - skanowanie portów
```
nmap -sS -Pn -vv --min-rate=40 --disable-arp-ping -p 1000-1100 10.0.0.2
```

### Uruchomienie nmapa - skanowanie różnych ip
```
nmap -sS -Pn -vv --min-rate=40 --disable-arp-ping -p 80 10.0.0.0/24
```