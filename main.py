import time
import numpy as np
import random
from joblib import Parallel, delayed

# Tabella di espansione
expansionTable = np.zeros(48)
# Le substitution boxes
substitutionBoxes = np.zeros((8, 4, 16))


# Funzione per convertire una stringa alfanumerica in una stringa binaria
def convert_string_to_binary(st):
    binary_string = ""
    for x in st:
        str = format(ord(x), 'b')
        while len(str) < 8:
            str = '0' + str
        binary_string += str
    return binary_string


# Funzione per convertire una stringa binaria in una stringa alfanumerica
def convert_binary_to_string(binary_string):
    string_converted = ""
    for i in range(0, len(binary_string), 8):
        string_converted += chr(int(binary_string[i:i + 8], 2))
    return string_converted


# Funzione per convertire un numero in una stringa binaria
def convert_decimal_to_binary(decimal):
    binary = ""
    while decimal != 0:
        binary = ("0" if decimal % 2 == 0 else "1") + binary
        decimal = decimal // 2
    while len(binary) < 4:
        binary = "0" + binary
    return binary


# Funzione per convertire una stringa binaria in un decimale
def convert_binary_to_decimal(binary):
    decimal = 0
    counter = 0
    for i in range(len(binary) - 1, -1, -1):
        if binary[i] == '1':
            decimal += 2 ** counter
        counter += 1
    return decimal


# Funzione per generare casualmente i valori della tabella di espansione e delle substitution boxes
def tables_filler():
    random.seed(time.time())
    for i in range(len(expansionTable)):
        expansionTable[i] = int(random.random() * 32) + 1

    for i in range(8):
        for j in range(4):
            for k in range(16):
                substitutionBoxes[i][j][k] = int(random.random() * 32)


# Funzione per generare le 16 chiavi in modo randomico
def generate_keys():
    random.seed(time.time())
    round_keys = []
    for i in range(16):
        round_key = ""
        for j in range(48):
            if (int(random.random() * 100) - j) % 2 == 0:
                round_key += "0"
            else:
                round_key += "1"
        round_keys.append(round_key)
    return round_keys


# Funzione per eseguire l'operazione di Xor tra due stringhe binarie
def xor(a, b):
    result = ""
    for i in range(len(b)):
        if a[i] != b[i]:
            result += "1"
        else:
            result += "0"
    return result


# Funzione per invertire le chiavi in modo da intercambiare tra encryption e decryption
def reverse_keys(round_keys):
    i = 15
    j = 0
    while i > j:
        temp = round_keys[i]
        round_keys[i] = round_keys[j]
        round_keys[j] = temp
        i -= 1
        j += 1
    return round_keys


# Implementazione dell'algoritmo DES
def DES(pt, round_keys):
    # Divide la stringa di plaintext in due parti uguali
    left = pt[0:32]
    right = pt[32:64]
    # Il plaintext viene criptato 16 volte
    for i in range(16):
        # La metà destra del plaintext viene espansa a 48 bit
        right_expanded = ""
        for j in expansionTable:
            right_expanded += right[int(j) - 1]

        # Viene fatto lo xor con la chiave corrispondente al round di encryption
        xored = xor(round_keys[i], right_expanded)
        res = ""

        # Il risultato viene diviso in 8 parti uguali e ognuna di esse viene passata attraverso le substitution boxes
        for k in range(8):
            # Trova l'indice della riga e della colonna da usare nella substitution box
            row1 = xored[k * 6] + xored[k * 6 + 5]
            row = convert_binary_to_decimal(row1)
            col1 = xored[k * 6 + 1] + xored[k * 6 + 2] + xored[k * 6 + 3] + xored[k * 6 + 4]
            col = convert_binary_to_decimal(col1)
            val = substitutionBoxes[k][row][col]
            res += convert_decimal_to_binary(val)

        # Il risultato della sostituzione viene messo in xor con la parte di sinistra del plaintext originale
        xored = xor(res, left)
        # Vengono scambiate la parte sinistra e destra per prepararsi al nuovo round
        left = xored
        # Tranne che all'ultimo round
        if i < 15:
            temp = right
            right = xored
            left = temp

    # Vengono rimesse insieme le due parti
    ciphertext = left + right
    return ciphertext


# Decriptazione sequenziale
def encryption_and_decryption_sequential(lines):
    is_correct = True
    tables_filler()
    round_keys = generate_keys()
    reverse_keys(round_keys)
    for line in lines:
        reverse_keys(round_keys)
        pt = convert_string_to_binary(line)
        ct = DES(pt, round_keys)
        reverse_keys(round_keys)
        decrypted = DES(ct, round_keys)
        # Comparing the initial plain text with the decrypted text
        x = convert_binary_to_string(decrypted)
        if x != line.strip():
            print(x)
            print(line)
            print("DECRIPTAZIONE FALLITA")
            print()
            is_correct = False
    return is_correct


# Decriptazione parallela
def encryption_and_decryption_parallel(lines, job):
    is_correct = True
    tables_filler()
    round_keys = generate_keys()
    Parallel(n_jobs=job)(delayed(single_en_dec)(line, round_keys) for line in lines)
    return is_correct


def single_en_dec(line, round_keys):
    reverse_keys(round_keys)
    pt = convert_string_to_binary(line)
    ct = DES(pt, round_keys)
    reverse_keys(round_keys)
    decrypted = DES(ct, round_keys)
    # Comparing the initial plain text with the decrypted text
    x = convert_binary_to_string(decrypted)
    if x != line.strip():
        print(x)
        print(line)
        print("DECRIPTAZIONE FALLITA")
        print()
        return False
    return True


if __name__ == '__main__':
    n_test = 2
    file = open('password.txt', 'r')
    Lines = file.readlines()
    start_time = time.time()
    encryption_and_decryption_sequential(Lines[0:5000])
    end_time = time.time()
    print(f'Tempo per decriptazione sequenziale: {end_time - start_time:.3f} s')
    # Test con 5000 password aumentando il numero di thread
    for i in range(2, 9, 1):
        test_time = 0
        for j in range(n_test):
            start_time = time.time()
            encryption_and_decryption_parallel(Lines[0:5000], i)
            end_time = time.time()
            test_time += end_time - start_time
        print(f'Tempo per decriptazione parallela con {i} jobs: {test_time/n_test:.3f} s')

    # Test aumentando il numero di password sequenziale:
    for i in range(5000, 11000, 1000):
        start_time = time.time()
        encryption_and_decryption_sequential(Lines[0:i])
        end_time = time.time()
        print(f'Tempo per decriptazione sequenziale di {i} password: {end_time - start_time:.3f} s')

    # Test aumentando il numero di password con 4 thread
    for i in range(5000, 11000, 1000):
        start_time = time.time()
        encryption_and_decryption_parallel(Lines[0:i], 4)
        end_time = time.time()
        print(f'Tempo per decriptazione parallela con 4 jobs di {i} password: {end_time - start_time:.3f} s')
