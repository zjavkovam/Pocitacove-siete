import socket
import os
import crc
import threading
from time import sleep


def make_fragment(flag, size, message):
    """
    B-start connection
    C-connection made sucessfully
    E-end connection
    F-conection eneded  unsucccessfully
    S-sent fragment
    D-file fragnent was delivered successfully
    U-fragment was delivered unsucccessfuly
    M-message
    N-filename
    K-keep alive message
    A-keep alive message was delivered
    T-timeout
    W-write into file, everthing was sent
    P-print message, everything was sent
    L-one or more fragments were lost and didnt arrived
    O-sending was successfull
    """
    flag = bytes(flag, 'ascii')
    size_bytes = size.to_bytes(4, byteorder='big')
    if isinstance(message, str):
        message = bytes(message, 'ascii')

    crc_calculator = crc.CrcCalculator(crc.Crc8.CCITT, True)
    checksum = (crc_calculator.calculate_checksum(message)).to_bytes(8, byteorder='big')

    message = flag + size_bytes + checksum + message
    return message


def begin_communication(message, udp_client_socket, buffer_size, server_address_port):
    print("Sending message to server to start connection")
    start_message = make_fragment('B', 0, message)
    udp_client_socket.sendto(start_message, server_address_port)

    message = udp_client_socket.recvfrom(buffer_size)[0]
    flag = message[:1].decode('ascii')

    if flag != 'C':
        print("Starting connection was unsuccessfull")
        exit(1)
    print("Starting connection successfully")


def end_communication(udp_client_socket, buffer_size, server_address_port):
    print("Sending request to end connection")
    end_message = make_fragment('E', 0, "Reqest to end connection from Client")
    udp_client_socket.sendto(end_message, server_address_port)
    message = udp_client_socket.recvfrom(buffer_size)
    data = message[0]
    flag = data[:1].decode('ascii')

    if flag == 'C':
        print("Connection ended successfully")
        return 0
    elif flag == 'F':
        print("Conection eneded  unsucccessfully")
        return


def connection_check(flag, fragment_flag, message, address, server_socket):
    if fragment_flag == flag:
        print(message)
        new_message = "Connection was made succesfully"
        new_fragment = make_fragment('C', 0, new_message)
        server_socket.sendto(new_fragment, address)
        return True
    else:
        print(message)
        new_message = "Connection failed"
        new_fragment = make_fragment('F', 0, new_message)
        server_socket.sendto(new_fragment, address)
        return False


def send_file(file_name, path, fragment_size, udp_client_socket, server_address_port):
    try:
        if len(path) > 0 and path[-1] != "/":
            path += "/"
        path += file_name
        file = open(path, "rb")
    except FileNotFoundError:
        print("File not found")
        return True
    size = os.path.getsize(path)
    buffer_size = fragment_size - 13
    fragment_count = size // buffer_size
    if size % buffer_size > 0:
        fragment_count += 1

    print("Absolute path:", os.path.abspath(path))
    print("Type: File, number of fragments:", fragment_count)
    print("Fragment size:", buffer_size)

    # send file name and fragment size
    fragment = make_fragment('N', fragment_count, file_name)
    fragment += buffer_size.to_bytes(2, byteorder='big')
    udp_client_socket.sendto(fragment, server_address_port)
    data = udp_client_socket.recvfrom(1472)[0]
    flag = data[:1].decode('ascii')
    if flag == 'U':
        print("sending first fragment was unsuccessful")
        send_file(file_name, fragment_size, udp_client_socket, server_address_port)
    print(data[13:].decode('ascii'))
    if flag == 'T':
        return False

    corrupt = True
    i = 0
    file_bytes = file.read(buffer_size)
    while True:
        print("Sending fragment N.", i + 1)
        if i == fragment_count - 1 and size % buffer_size != 0:
            buffer_size = size % (fragment_size-13)
        fragment = make_fragment('S', i + 1, file_bytes)

        if corrupt:
            last = fragment[-1:]
            fragment = fragment[:13] + last + fragment[13:-1]
            corrupt = False
        udp_client_socket.sendto(fragment, server_address_port)

        data = udp_client_socket.recvfrom(1472)[0]
        flag = data[:1].decode('ascii')
        message = data[13:].decode('ascii')
        print(message)

        if flag != 'U':
            i += 1
            file_bytes = file.read(buffer_size)

        if flag == 'T':
            print(data[13:].decode('ascii'))
            return False

        if i == fragment_count:
            break

    fragment = make_fragment('W', fragment_count, "All fragments were sent")
    udp_client_socket.sendto(fragment, server_address_port)
    data = udp_client_socket.recvfrom(1472)[0]
    flag = data[:1].decode('ascii')
    if flag == "O":
        print("File was sent successfully")
    elif flag == "L":
        print("Fragments were lost")

    return True


def send_message(message, fragment_size, udp_client_socket, server_address_port):
    size = len(message)
    buffer_size = fragment_size - 13
    fragment_count = size // buffer_size
    if size % buffer_size > 0:
        fragment_count += 1

    # send number of fragments
    print("Type: Message, number of fragments:", fragment_count)
    print("Fragment size:", buffer_size)
    fragment = make_fragment('M', fragment_count, "message")
    fragment += buffer_size.to_bytes(2, byteorder='big')
    udp_client_socket.sendto(fragment, server_address_port)
    data = udp_client_socket.recvfrom(1472)[0]
    flag = data[:1].decode('ascii')
    if flag == 'U':
        print("sending first fragment was unsuccessful")
        send_message(message, fragment_size, udp_client_socket, server_address_port)
    print(data[13:].decode('ascii'))

    if flag == 'T':
        return False

    corrupt = True
    i = 0
    while True:
        print("Sending fragment N.", i + 1)
        if i == fragment_count - 1 and size % buffer_size != 0:
            buffer_size = size % (fragment_size-13)

        message_part = message[:buffer_size]

        fragment = make_fragment('M', i + 1, message_part)
        if corrupt:
            last = fragment[-1:]
            fragment = fragment[:13] + last + fragment[13:-1]
            corrupt = False
        udp_client_socket.sendto(fragment, server_address_port)

        data = udp_client_socket.recvfrom(1472)[0]
        flag = data[:1].decode('ascii')
        server_message = data[13:].decode('ascii')
        print(server_message)

        if flag == 'T':
            print(data[13:].decode('ascii'))
            return False

        if flag != 'U':
            i += 1
            message = message[buffer_size:]

        if i == fragment_count:
            break

    fragment = make_fragment('P', fragment_count, "All fragments were sent")
    udp_client_socket.sendto(fragment, server_address_port)
    data = udp_client_socket.recvfrom(1472)[0]
    flag = data[:1].decode('ascii')
    if flag == "O":
        print("Message was sent successfully")
    elif flag == "L":
        print("Fragments were lost")
    return True


def get_buffer_size():
    while True:
        buffer_size = int(input("Enter max. fragment size (1-1459): "))
        if buffer_size < 0 or buffer_size > 1459:
            print("Wrong fragment size")
            continue
        else:
            return buffer_size+13


def keepalive(stop, udp_client_socket, server_address_port):
    while True:
        sleep(10)
        if stop():
            break
        fragment = make_fragment('K', 0, "Keep Alive")
        udp_client_socket.sendto(fragment, server_address_port)
        data = udp_client_socket.recvfrom(1459)[0]
        flag = data[:1].decode('ascii')
        if flag == 'A':
            message = data[13:].decode('ascii')
            # print(message)


def client(ip, port):
    print("Starting Client program")
    server_address_port = (ip, port)
    buffer_size = 1472
    udp_client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    begin_communication("Inicialization of connection", udp_client_socket, buffer_size, server_address_port)

    stop_thread = True
    t1 = threading.Thread(target=keepalive, args=(lambda: stop_thread, udp_client_socket, server_address_port))
    t1.start()

    while True:
        type = input("1. Send file\n2. Send message\n3. End\n")

        if type == "1":
            path = input("File path:")
            file_name = input("File name: ")
            buffer_size = get_buffer_size()

            stop_thread = True
            if not send_file(file_name, path, buffer_size, udp_client_socket, server_address_port):
                return
            stop_thread = False
            t1 = threading.Thread(target=keepalive, args=(lambda: stop_thread, udp_client_socket, server_address_port))
            t1.start()

        elif type == "2":
            buffer_size = get_buffer_size()
            message = input("Message to send:\n")

            stop_thread = True
            if not send_message(message, buffer_size, udp_client_socket, server_address_port):
                return
            stop_thread = False
            t1 = threading.Thread(target=keepalive, args=(lambda: stop_thread, udp_client_socket, server_address_port))
            t1.start()

        elif type == "3":
            stop_thread = True
            end_communication(udp_client_socket, buffer_size, server_address_port)
            return
        else:
            print("wrong input")


def check_sum(udp_server_socket, fragment_number, address, data):
    expected_checksum = int.from_bytes(data[5:13], "big")
    crc_calculator = crc.CrcCalculator(crc.Crc8.CCITT)
    checksum = crc_calculator.calculate_checksum(data[13:])
    if checksum == expected_checksum and crc_calculator.verify_checksum(data[13:], expected_checksum):
        fragment = make_fragment('D', 0, "Fragment delivered successfully")
        udp_server_socket.sendto(fragment, address)
        print("Fragment " + str(fragment_number) + " was sent successfully")
        return True

    else:
        fragment = make_fragment('U', 0, "Fragment was not delivered successfully")
        udp_server_socket.sendto(fragment, address)
        print("Fragment " + str(fragment_number) + " was not sent successfully, requesting fragment again")
        return False


def server(local_ip, local_port):
    buffer_size = 1472
    udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_server_socket.bind((local_ip, local_port))
    udp_server_socket.settimeout(20000)
    print("UDP server up and listening")

    # Listen for incoming datagrams
    connection = False
    message = ""
    file_bytes = bytearray()
    fragment_count = 0
    chybne = 0
    while True:
        try:
            bytes_address_pair = udp_server_socket.recvfrom(buffer_size)
            data = bytes_address_pair[0]
            address = bytes_address_pair[1]
            flag = data[:1].decode('ascii')

            if not connection:
                fragment_message = data[13:].decode('ascii')
                connection = connection_check('B', flag, fragment_message, address, udp_server_socket)

            else:
                # ending message
                if flag == 'E':
                    message = data[13:].decode('ascii')
                    print(message)
                    print("Sending back confirmation about ending connection")
                    new_fragment = make_fragment('C', 0, "Connection ended succesfully")
                    udp_server_socket.sendto(new_fragment, address)
                    return

                # keep alive message
                if flag == 'K':
                    k_message = data[13:].decode('ascii')
                    print(k_message)
                    new_fragment = make_fragment('A', 0, "Keep Alive message sent successfully")
                    udp_server_socket.sendto(new_fragment, address)

                # file name
                if flag == 'N':
                    name = data[13:-2].decode('ascii')
                    file_name = name
                    fragment_count = int.from_bytes(data[1:5], "big")
                    fragment_size = int.from_bytes(data[-2:], "big")
                    fragment = make_fragment('D', 0, "File name delivered successfuly")
                    udp_server_socket.sendto(fragment, address)
                    print("File name: " + file_name + ", Number of fragments: ", fragment_count)
                    print("Fragment size:", fragment_size)

                    path = input("Directory, where to save file: ")
                    if len(path) != 0 and path[-1] != "/":
                        path += "/"
                    path += file_name
                    new_file = open(path, 'wb')

                # accept fragments to file
                elif flag == 'S':
                    fragment_number = int.from_bytes(data[1:5], "big")
                    succesfully_delivered = check_sum(udp_server_socket, fragment_number, address, data)
                    if succesfully_delivered:
                        file_bytes += data[13:]

                elif flag == 'M':
                    if fragment_count == 0:
                        fragment_count = int.from_bytes(data[1:5], "big")
                        fragment_size = int.from_bytes(data[-2:], "big")
                        fragment = make_fragment('D', 0, "Number of fragments delivered successfuly")
                        udp_server_socket.sendto(fragment, address)
                        print("Sending message, Number of fragments: ", fragment_count)
                        print("Fragment size:", fragment_size)

                    else:
                        fragment_number = int.from_bytes(data[1:5], "big")
                        succesfully_delivered = check_sum(udp_server_socket, fragment_number, address, data)

                        if succesfully_delivered:
                            message += data[13:].decode('ascii')

                elif flag == "P":
                    if fragment_count == fragment_number and succesfully_delivered:
                        print("Message was sent successfully.")
                        fragment = make_fragment('O', 0, "Message was delivered successfully")
                    else:
                        print("Not all fragments were sent")
                        fragment = make_fragment('L', 0, "Message was not delivered successfully")

                    udp_server_socket.sendto(fragment, address)
                    print("Message:\n" + message)
                    message = ""
                    fragment_count = 0

                elif flag == "W":
                    new_file.write(file_bytes)
                    if fragment_count == fragment_number and succesfully_delivered:
                        print("File was sent successfully.")
                        fragment = make_fragment('O', 0, "File was delivered successfully")
                    else:
                        print("Not all fragments were sent")
                        fragment = make_fragment('L', 0, "File was not delivered successfully")

                    udp_server_socket.sendto(fragment, address)
                    file_bytes = bytearray()
                    fragment_count = 0
                    print("Absolute path:", os.path.abspath(path))


        except socket.timeout:
            print("TIMEOUT")
            fragment = make_fragment('T', 0, "TIMEOUT")
            udp_server_socket.sendto(fragment, address)
            return


def menu():
    first_default = "192.168.0.11"
    second_default = "192.168.0.19"
    server_ip = first_default
    port = 20000

    while True:
        vstup = input("Run as:\n1.Client\n2.Server\n3.Change server ip address\n4.Change port\n5.End\n")
        if vstup == "1":
            client(server_ip, port)
        elif vstup == "2":
            server(server_ip, port)
        elif vstup == "3":
            change = input("1. first default\n 2. second default\n3.write in console\n")
            if change == "1":
                server_ip = first_default
            elif change == "2":
                server_ip = second_default
            elif change == "3":
                server_ip = input("New IP address: ")
            else:
                print("wrong input")
        elif vstup == "4":
            port = input("New port:")
        elif vstup == "4":
            return
        else:
            print("Zle zadaný vstup")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    menu()
