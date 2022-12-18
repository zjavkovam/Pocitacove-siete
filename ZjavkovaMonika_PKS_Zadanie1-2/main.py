import scapy.all as scapy

zdrojove = []
protokoly = {"HTTP": [], "HTTPS": [], "TELNET": [], "SSH": [], "FTP dátove": [], "FTP riadiace": []}
UDP = []
ICMP = []
ARP = []
LLC = {}
ET = {}
TCP = {}
prot = {}
ICMP_type = {}

# Načítanie údajov do slovníkov o portoch a protokoloch
def nacitaj_udaje():
    llc = open("LLC.txt", "r")
    for i in llc:
        cislo = i.split()[0]
        LLC[cislo] = i[len(cislo) + 1:-1]
    llc.close()

    file = open("EtherType.txt", "r")
    for i in file:
        cislo = i.split()[0]
        ET[cislo] = i[len(cislo) + 1:-1]
    file.close()

    f = open("Protokoly.txt", "r")
    for i in f:
        cislo = i.split()[0]
        prot[cislo] = i[len(cislo) + 1:-1]
    f.close()

    file = open("ICMP.txt", "r")
    for i in file:
        cislo = i.split()[0]
        ICMP_type[cislo] = i[len(cislo) + 1:-1]
    file.close()

#vráti naformátovanú mac adresu ako string
def vypis_mac(adresa):
    mac_adresa = ""
    for i in range(0, 12, 2):
        mac_adresa += adresa[i].capitalize() + adresa[i + 1].capitalize() + " "
    return mac_adresa


def vypis_raw(raw):
    print("\n", end="")
    for i in range(1, len(raw) + 1):
        print(raw[i - 1].capitalize(), end="")
        if (i % 2 == 0):
            print(" ", end="")
        if (i % 16 == 0):
            print(" ", end="")
        if (i % 32 == 0):
            print("\n", end="")


def vypis_raw_subor(raw, file):
    file.write("\n")
    for i in range(1, len(raw) + 1):
        file.write(raw[i - 1].capitalize())
        if (i % 2 == 0):
            file.write(" ")
        if (i % 16 == 0):
            file.write(" ")
        if (i % 32 == 0):
            file.write("\n")


#Úloha 3 - nájde najčastejšie vyskytovanú ip adresu
def najcastejsia_ip(adresy):
    ip = {}
    for adresa in adresy:
        if adresa in ip:
            ip[adresa] += 1
        else:
            ip[adresa] = 1

    maximum = max(ip, key=ip.get)
    return [ip.get(maximum), maximum]


def najdi_typ(byty):
    if (byty == "aa"):
        return "802.3 - SNAP"
    elif (byty == "ff"):
        return "802.3 RAW"
    else:
        return "802.3 - LLC "


#Určí protokol na Aplikačnej vrstve
def vnorene_protokoly(raw, Sport, Dport, nad_protokol):
    if nad_protokol == "TCP":
        f = open("TCP.txt", "r")
        for riadok in f:
            cislo = riadok.split()[0]
            if int(cislo) == Sport or int(cislo) == Dport:
                for i in protokoly:
                    if i == riadok[len(cislo) + 1:-1]:
                        protokoly[i].append(raw)

    elif nad_protokol == "UDP":
        UDP.append(raw + " " + str(Sport) + " " + str(Dport))


def vypisanie_protokolov(typ, zoznam):
    print(typ, "PROTOKOLY:")
    dlzka = len(zoznam)
    if dlzka > 20:
        zoznam = zoznam[:10] + zoznam[-10:]

    for i in zoznam:
        print("Rámec", i.split()[0])
        raw = i.split()[1]
        zakladny_vypis(raw, "Ethernet II")
        print("\nIPv4")
        adresy = ip_adresy(raw)
        print("Cieľová IP adresa: " + adresy[0])
        print("Zdrojová IP adresa: " + adresy[1])
        print("TCP")
        print(typ)
        print("Zdrojový port:", adresy[3])
        print("Cieľový port:", adresy[2], end="")
        vypis_raw(raw)
        print("\n")


def analyza_tftp():
    komunikacie = {}
    c_komunikacie = 1
    pridavanie_do_komunikacie = False
    predchadzajuci_port = ""

    for i in UDP:

        data = i.split()
        raw = data[1]
        Sport = data[2]
        Dport = data[3]

        # prechádza UDP, kým nenájde port 69
        if Dport == "69":
            komunikacie[c_komunikacie] = []
            komunikacie[c_komunikacie].append(i)
            pridavanie_do_komunikacie = True

        #ak je začiatok, pridávajú sa do komunikácie ďalšie rámce, kde sa zhodujú porty
        if pridavanie_do_komunikacie:
            if predchadzajuci_port == Dport:
                komunikacie[c_komunikacie].append(i)
            elif Dport != "69":
                pridavanie_do_komunikacie = False
                c_komunikacie += 1
        predchadzajuci_port = Sport

    #vypísanie protokolov
    print("TFTP PRORTOKOL:")
    for komunikacia in komunikacie:

        zoznam = komunikacie[komunikacia]
        print(len(zoznam))
        if len(zoznam) > 20:
            zoznam = komunikacie[komunikacia][:10] + komunikacie[komunikacia][-10:]

        print("Komunikácia č." + str(komunikacia))
        for i in zoznam:
            data = i.split()
            raw = data[1]

            print("Rámec", data[0])
            zakladny_vypis(raw, "Ethernet II")
            print("\nIPv4")
            adresy = ip_adresy(raw)
            print("Cieľová IP adresa: " + adresy[0])
            print("Zdrojová IP adresa: " + adresy[1])
            print("UDP")
            print("TFTP")
            print("Zdrojový port:", adresy[3])
            print("Cieľový port:", adresy[2], end="")
            vypis_raw(raw)
            print("\n")


def analyza_icmp():
    cislo_komunikacie = 1
    for i in ICMP:

        data = i.split()
        raw = data[1]
        adresy = ip_adresy(raw)

        type = ""
        for i in ICMP_type:
            if (i == data[2]):
                type = ICMP_type[i]

        if (type != "Echo Reply"):
            print("Komunikácia ", str(cislo_komunikacie))
            cislo_komunikacie += 1
        print("Rámec", data[0])
        zakladny_vypis(raw, "Ethernet II")
        print("\nIPv4")
        print("Cieľová IP adresa: " + adresy[0])
        print("Zdrojová IP adresa: " + adresy[1])
        print("ICMP")
        print("Typ ICMP správy:", type, end="")
        vypis_raw(raw)
        print("\n")


def arp_udaje(raw):
    operacia = raw[15:16]

    if operacia == "1":
        operacia = "ARP-Request"
    else:
        operacia = "ARP-Replay"

    Dip = raw[48:56]
    Sip = raw[28:36]
    cielova_IP = str(int(Dip[:2], 16)) + "." + str(int(Dip[2:4], 16)) + "." + str(int(Dip[4:6], 16)) + "." + str(
        int(Dip[6:], 16))
    cielova_MAC = vypis_mac(raw[36:48])
    zdrojova_IP = str(int(Sip[:2], 16)) + "." + str(int(Sip[2:4], 16)) + "." + str(int(Sip[4:6], 16)) + "." + str(
        int(Sip[6:], 16))

    return [operacia, cielova_IP, cielova_MAC, zdrojova_IP]


def analyza_arp():
    global nove_udaje
    cislo_komunikacie = 1
    sparovanie = False

    for i in list(ARP):
        data = i.split()
        hladane_udaje = arp_udaje(data[1][28:])
        komunikacia = [i]


        #keď nájde ARP request, hľadá, či nie je v rámcoch ďalší rovnaký
        if (hladane_udaje[0] == "ARP-Request" and i in ARP):
            n = ARP.index(i) + 1
            while n < len(ARP):

                data = ARP[n].split()
                nove_udaje = arp_udaje(data[1][28:])

                if hladane_udaje[1] == nove_udaje[1] and hladane_udaje[3] == nove_udaje[3] and nove_udaje[0] == "ARP-Request":
                    komunikacia.append(ARP[n])

                #keď nájde Reply, vypíše dvojicu
                if nove_udaje[3] == hladane_udaje[1] and nove_udaje[1] == hladane_udaje[3] and nove_udaje[
                    0] == "ARP-Replay":
                    komunikacia.append(ARP[n])
                    sparovanie = True
                    break

                n += 1

            if (sparovanie):
                print("Komunikácia č.", cislo_komunikacie)
                print(hladane_udaje[0], ", IP adresa:", hladane_udaje[1], ", MAC adresa: ???\nZdrojová IP:",
                      hladane_udaje[3], ", Cieľová IP:", hladane_udaje[1])

                for k in komunikacia:
                    if komunikacia.index(k) == len(komunikacia) - 1:
                        print("\n" + nove_udaje[0], ", IP adresa:", nove_udaje[1], ", MAC adresa:", nove_udaje[2],
                              "\nZdrojová IP:", nove_udaje[3], ", Cieľová IP:", nove_udaje[1])
                    data = k.split()
                    print("Rámec č.", data[0])
                    zakladny_vypis(data[1], "Ethernet II")
                    print("\nARP", end="")
                    vypis_raw(data[1])
                    print("\n")
                    ARP.remove(k)

                sparovanie = False
                cislo_komunikacie += 1


    #Ak nenájde, vypíše všetky ostávajúce rámce, ktoré neboli spárované
    vypisanie = input("Vypísať nespárované rámce? a/n\n")
    if (vypisanie == "a"):
        print("NESPÁROVANÉ KOMUNIKÁCIE:")

        for i in list(ARP):

            data = i.split()
            hladane_udaje = arp_udaje(data[1][28:])
            komunikacia = [i]

            if i in ARP:
                n = ARP.index(i) + 1
                while n < len(ARP):

                    data = ARP[n].split()
                    nove_udaje = arp_udaje(data[1][28:])

                    if hladane_udaje[1] == nove_udaje[1] and hladane_udaje[3] == nove_udaje[3] and nove_udaje[0]=="ARP-Request":
                        komunikacia.append(ARP[n])

                    n += 1

                print("Komunikácia č.", cislo_komunikacie)
                print(hladane_udaje[0], ", IP adresa:", hladane_udaje[1], ", MAC adresa:",hladane_udaje[2],"\nZdrojová IP:",hladane_udaje[3], ", Cieľová IP:", hladane_udaje[1])

                for k in komunikacia:
                    data = k.split()
                    print("Rámec č.", data[0])
                    zakladny_vypis(data[1], "Ethernet II")
                    print("\nARP", end="")
                    vypis_raw(data[1])
                    print("\n")
                    ARP.remove(k)
                    cislo_komunikacie += 1


def analyza_TCP(typ):
    z_handshake = {1: 2, 2: 12, 3: 10}
    ramce = protokoly[typ]
    uplna_komunikacia = []
    neuplna_komunikacia = []

    for i in list(ramce):

        raw = i.split()[1]
        flags = int(raw[94:96])
        adresy = ip_adresy(raw)
        zdrojovy_port = adresy[3]
        cielovy_port = adresy[2]

        if flags == 2:

            hladam = 2
            n = protokoly[typ].index(i) + 1
            zaciatok = False
            ukoncenie = False
            komunikacia = [i]

            #Nájdenie začiatku komunikácie
            while n < len(ramce):

                raw = ramce[n].split()[1]
                adresy = ip_adresy(raw)
                novy_zdrojovy_port = adresy[3]
                novy_cielovy_port = adresy[2]

                if cielovy_port == novy_zdrojovy_port and zdrojovy_port == novy_cielovy_port:
                    flags = int(raw[94:96])

                    # kontrola ACK a SYN, či sa nachádzajú vo flags
                    if flags == z_handshake[hladam]:
                        hladam += 1
                        komunikacia.append(ramce[n])
                        zdrojovy_port = adresy[3]
                        cielovy_port = adresy[2]

                    # vyskytuju sa tam
                    if hladam > 3:
                        zaciatok = True
                        n+=1
                        break

                n += 1

            #Ak sa našiel začiatok, pokračuje analyzovanie komunikácie ďalej
            if (zaciatok):

                while (n<len(ramce)):
                    raw = ramce[n].split()[1]
                    adresy = ip_adresy(raw)
                    novy_zdrojovy_port = adresy[3]
                    novy_cielovy_port = adresy[2]
                    flags = int(raw[94:96])

                    if((cielovy_port == novy_cielovy_port or cielovy_port == novy_zdrojovy_port) and
                            (zdrojovy_port == novy_zdrojovy_port or zdrojovy_port == novy_cielovy_port)):

                        #Ak sa našiel rámec súčasťou komunikácie, pridá sa do pola
                        if flags == 10 or flags == 18:
                            komunikacia.append(ramce[n])
                            zdrojovy_port = novy_zdrojovy_port
                            cielovy_port = novy_cielovy_port

                        #ak je to ukončenie komunikácie, cyklus skončí
                        if(flags == 11 or flags == 1 or flags == 4):
                            komunikacia.append(ramce[n])
                            zdrojovy_port = novy_zdrojovy_port
                            cielovy_port = cielovy_port
                            ukoncenie = True
                            if(flags == 4):
                                break
                    n += 1

            if(ukoncenie):
                if(uplna_komunikacia == []):
                    uplna_komunikacia = komunikacia
            else:
                if (neuplna_komunikacia == []):
                    neuplna_komunikacia = komunikacia


        if(neuplna_komunikacia != [] and uplna_komunikacia != []):
            break

    i = input("Vypísať úplnú alebo neúplnú? u/n\n")
    if(i == "u"):
        print("ÚPLNÁ KOMUNIKÁCIA")
        vypisanie_protokolov(typ, uplna_komunikacia)
        print("\n")
    elif(i == "n"):
        print("NEÚPLNÁ KOMUNIKÁCIA")
        vypisanie_protokolov(typ, neuplna_komunikacia)
        print("\n")


def ip_adresy(raw_povodne):
    raw = raw_povodne[28:]
    dlzka = raw[1:2]
    hlavicka = (4 * int(dlzka)) * 2

    Dip = raw[hlavicka - 8:hlavicka]
    Sip = raw[hlavicka - 16:hlavicka - 8]

    DIP = str(int(Dip[:2], 16)) + "." + str(int(Dip[2:4], 16)) + "." + str(int(Dip[4:6], 16)) + "." + str(
        int(Dip[6:], 16))
    SIP = str(int(Sip[:2], 16)) + "." + str(int(Sip[2:4], 16)) + "." + str(int(Sip[4:6], 16)) + "." + str(
        int(Sip[6:], 16))

    Sport = int(raw[hlavicka:hlavicka + 4], 16)
    Dport = int(raw[hlavicka + 4:hlavicka + 8], 16)
    return [DIP, SIP, Dport, Sport]


def ipv4(raw_povodne, poradove_cislo, file):
    raw = raw_povodne[28:]
    hlavicka = (4 * int(raw[1:2])) * 2
    c_protokol = int(raw[hlavicka - 22:hlavicka - 20], 16)

    protokol = "Unknown"
    file.write("\n")
    for i in prot:
        if c_protokol == int(i):
            protokol = prot[i]

    if (protokol == "ICMP"):
        type = int(raw[hlavicka:hlavicka + 2], 16)
        ICMP.append(str(poradove_cislo) + " " + raw_povodne + " " + str(type))

    adresy = ip_adresy(raw_povodne)
    file.write("Cieľová IP adresa: " + adresy[0] + "\n")
    file.write("Zdrojová IP adresa: " + adresy[1] + "\n")
    file.write(protokol)
    zdrojove.append(adresy[1])

    Sport = adresy[3]
    Dport = adresy[2]
    vnorene_protokoly(str(poradove_cislo) + " " + raw_povodne, Sport, Dport, protokol)


def dlzka(dlzka):
    if (dlzka >= 64):
        return dlzka + 4
    else:
        return 64


def zakladny_vypis(raw, typ):
    Dmac = vypis_mac(raw[0:12])
    Smac = vypis_mac(raw[12:24])
    dlzka_ramca = len(raw) / 2

    print("Dĺžka rámca poskytnutá pcap - ", dlzka_ramca, "B")
    print("Dĺžka rámca prenášaného po médiu - ", dlzka(dlzka_ramca), "B")
    print(typ)
    print("Cieľová MAC adresa:", Dmac)
    print("Zdrojová MAC adresa:", Smac, end="")


def zakladny_vypis_subor(raw, typ, f):
    Dmac = vypis_mac(raw[0:12])
    Smac = vypis_mac(raw[12:24])
    dlzka_ramca = len(raw) / 2

    print("Dĺžka rámca poskytnutá pcap - ", dlzka_ramca, "B", file=f)
    print("Dĺžka rámca prenášaného po médiu - ", dlzka(dlzka_ramca), "B", file=f)
    f.write(typ + "\n")
    print("Cieľová MAC adresa:", Dmac, file=f)
    print("Zdrojová MAC adresa:", Smac, file=f)


def main():
    n = 1

    # Súbor s pcap súbormi
    pcap = scapy.rdpcap("vzorky/trace-27.pcap")
    file = open("vystup.txt", "w")
    for pkt in pcap:
        raw = scapy.raw(pkt).hex()
        nacitaj_udaje()

        file.write("Rámec " + str(n) + "\n")

        # Dĺžka/typ
        if ((int(raw[24:28], 16)) > 1500):
            zakladny_vypis_subor(raw, "Ethernet II", file)
            typ = "Unknown"
            for i in ET:
                if (i == raw[24:28]):
                    typ = ET[i]
            file.write(typ)
            if (typ == "IPv4"):
                ipv4(raw, n, file)
            elif (typ == "ARP"):
                ARP.append(str(n) + " " + raw)

        else:
            typ = najdi_typ(raw[28:30])
            zakladny_vypis_subor(raw, typ, file)
            file.write("")
            if (typ == "802.3 RAW"):
                file.write("IPX")
            elif (typ == "802.3 - LLC "):
                for i in LLC:
                    if (i == raw[28:30]):
                        file.write(LLC[i])
                        break

        vypis_raw_subor(raw, file)
        file.write("\n\n")
        n += 1

    while True:
        print("1 - IP adresy\n2 - HTTP\n3 - HTTPS\n4 - TELNET\n5 - SSH\n6 - FTP dátové\n7 - FTP riadiace\n8 - TFTP\n9 - ICMP\n10 - ARP dvojice")
        zadanie = input()
        if not zadanie:
            break
        if zadanie == "1":
            print("IP adresy vysielajúcich uzlov:")
            for i in zdrojove:
                print(i)

            maximum = najcastejsia_ip(zdrojove)
            print("\nAdresa uzla s najväčším počtom odoslaných paketov:")
            print(maximum[1], " ", maximum[0], "paketov")
        elif zadanie == "2":
            analyza_TCP("HTTP")
        elif zadanie == "3":
            analyza_TCP("HTTPS")
        elif zadanie == "4":
            analyza_TCP("TELNET")
        elif zadanie == "5":
            analyza_TCP("SSH")
        elif zadanie == "6":
            analyza_TCP("FTP dátove")
        elif zadanie == "7":
            analyza_TCP("FTP riadiace")
        elif zadanie == "8":
            analyza_tftp()
        elif zadanie == "9":
            analyza_icmp()
        elif zadanie == "10":
            analyza_arp()


main()
