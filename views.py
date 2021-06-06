from random import randint

from django.shortcuts import render
from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)


class Characters:
    def __init__(self, char, freq) -> None:
        self._char = char
        self._freq = freq
        self._code = ""

    def __lt__(self, other):
        return True if self._freq < other.get_freq() else False

    def __str__(self):
        return "{0}\t {1}\t {2}".format(self._char, str(self._freq), self._code)

    def __iter__(self):
        return self

    def get_char(self):
        return self._char

    def get_freq(self):
        return self._freq

    def get_code(self):
        return self._code

    def append_code(self, code):
        self._code += str(code)


def DivideList(lst):
    if len(lst) == 1:
        return None
    s = k = b = 0
    for p in lst:
        s += p.get_freq()
    s /= 2
    for p in range(len(lst)):
        k += lst[p].get_freq()
        if k == s:
            return p
        elif k > s:
            j = len(lst) - 1
            while b < s:
                b += lst[j].get_freq()
                j -= 1
            return p if abs(s - k) < abs(s - b) else j
    return


def Shannon_fano_code(lst):
    middle = DivideList(lst)
    if middle is None:
        return
    for i in lst[: middle + 1]:
        i.append_code(0)
    Shannon_fano_code(lst[: middle + 1])
    for i in lst[middle + 1:]:
        i.append_code(1)
    Shannon_fano_code(lst[middle + 1:])


def ShannonDecode(dictionary, text):
    res = ""
    while text:
        for k in dictionary:
            if text.startswith(k):
                res += dictionary[k]
                text = text[len(k):]
    return res


def sorted_probability(sorting_list):
    desc = sorted(sorting_list, key=lambda x: x[1], reverse=True)
    return desc


def get_all(probabilities):
    lst = []
    for key, value in probabilities:
        lst.append(Characters(key, value))
    return lst


def check(initial):
    r1 = list(initial)
    l = len(initial)
    global z

    if l % 4 == 1:
        r1.append('000')
        z = 3
    if l % 4 == 2:
        r1.append('00')
        z = 2
    if l % 4 == 3:
        r1.append('0')
        z = 1
    if l % 4 == 0:
        z = 0
    r2 = ''.join(r1)
    return r2


def remove(decoded, z):
    for i in range(z):
        decoded = decoded[:-1]
    return decoded


def HammingEncode(initial):
    lst = []
    encode = []
    result_h = ''
    result = ''
    for i in initial:
        encode.append(i)
        if len(encode) == 4:
            a = ''.join(encode)
            lst.append(a)
            encode = []
    for i in lst:
        r1 = int(i[0]) ^ int(i[1]) ^ int(i[2])
        r2 = int(i[1]) ^ int(i[2]) ^ int(i[3])
        r3 = int(i[0]) ^ int(i[1]) ^ int(i[3])
        i += str(r1) + str(r2) + str(r3)
        result += i + ' '
        result_h += i
    return result_h


def Divide_7(encoded):
    lst2 = []
    encode = []
    for i in encoded:
        encode.append(i)
        if len(encode) == 7:
            a = ''.join(encode)
            lst2.append(a)
            encode = []
    return list(lst2)


def error(tst):
    test = Divide_7(tst)
    size = len(test)
    error_list = []
    for i in range(0, size):
        while True:
            errored_num = randint(0, size - 1)
            c = [i for i in error_list if i == errored_num]
            if len(c) == 0:
                break
            else:
                continue
        error_list.append(errored_num)
        ranpos = randint(0, len(test[errored_num]) - 1)
        if test[errored_num][ranpos] == '0':
            test[errored_num] = test[errored_num][:ranpos] + '1' + test[errored_num][ranpos + 1:]
        else:
            test[errored_num] = test[errored_num][:ranpos] + '0' + test[errored_num][ranpos + 1:]
    error_list.sort()
    errors = ''.join(test)
    return errors


def HammingErrorCorrection(encoded):
    lst2 = []
    encode = []
    res1 = []
    for i in encoded:
        encode.append(i)
        if len(encode) == 7:
            a = ''.join(encode)
            lst2.append(a)
            encode = []
    for i in lst2:
        r1 = i[4]
        r2 = i[5]
        r3 = i[6]
        s1 = int(r1) ^ int(i[0]) ^ int(i[1]) ^ int(i[2])
        s2 = int(r2) ^ int(i[1]) ^ int(i[2]) ^ int(i[3])
        s3 = int(r3) ^ int(i[0]) ^ int(i[1]) ^ int(i[3])
        s = str(s1) + str(s2) + str(s3)
        if s == '000':
            error_bit = 'No error'
        elif s == '001':
            if r3 == '0':
                i = i[:6] + '1' + i[6 + 1:]
            else:
                i = i[:6] + '0' + i[6 + 1:]
        elif s == '010':
            if r2 == '0':
                i = i[:5] + '1' + i[5 + 1:]
            else:
                i = i[:5] + '0' + i[5 + 1:]

        elif s == '011':
            if i[3] == '0':
                i = i[:3] + '1' + i[3 + 1:]
            else:
                i = i[:3] + '0' + i[3 + 1:]
        elif s == '100':
            if r1 == '0':
                i = i[:4] + '1' + i[4 + 1:]
            else:
                i = i[:4] + '0' + i[4 + 1:]
        elif s == '101':
            if i[0] == '0':
                i = i[:0] + '1' + i[0 + 1:]
            else:
                i = i[:0] + '0' + i[0 + 1:]
        elif s == '110':
            if i[2] == '0':
                i = i[:2] + '1' + i[2 + 1:]
            else:
                i = i[:2] + '0' + i[2 + 1:]
        elif s == '111':
            if i[1] == '0':
                i = i[:1] + '1' + i[1 + 1:]
            else:
                i = i[:1] + '0' + i[1 + 1:]
        else:
            print('Unavailable checking')
        res1 += i  # + ' '
    return ''.join(res1)


def HammingDecoding(encode):
    new_one = Divide_7(encode)
    decoded = []
    final = ''
    for j in new_one:
        decoded += str(j[0]) + str(j[1]) + str(j[2]) + str(j[3])
        final = ''.join(decoded)
    return final


def compression_ratio(text1, text2):
    comp_rat = (len(text1) * 8) / (len(text2))
    return comp_rat


def index(request):
    return render(request, "input.html")


def theory1(request):
    return render(request, "index.html")


def theory2(request):
    return render(request, "theory2.html")


def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag


def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


def get_result(request):
    msg = request.POST['num1']
    nonce, ciphertext, tag = encrypt(msg)
    plaintext = decrypt(nonce, ciphertext, tag)
    total = len(plaintext)
    all_freq = {}
    lists = []
    r = ""
    code = []
    char = []

    for i in msg:
        all_freq[i] = msg.count(i)
    for key, value in all_freq.items():
        prob = round(value / total, 4)
        lists.append((key, prob))

    result = sorted_probability(lists)
    all = get_all(result)
    all.sort(reverse=True)
    encoded_data = []
    Shannon_fano_code(all)
    for c in all:
        encoded_data.append(c)
    for u in msg:
        for n in all:
            if u == n.get_char():
                r += str(n.get_code())
    for k in all:
        code.append(k.get_code())
        char.append(k.get_char())
    dictionary = dict(zip(code, char))
    renew = r
    renew = check(initial=renew)
    hammming = HammingEncode(initial=renew)
    test = error(tst=hammming)
    correction = HammingErrorCorrection(encoded=test)
    decoded_hamming = HammingDecoding(encode=correction)
    var = remove(decoded=decoded_hamming, z=z)
    decodedFill = ShannonDecode(dictionary=dictionary, text=var)
    ratio = compression_ratio(text1=msg, text2=r)
    return render(request, "input.html", {
        "cipher": ciphertext,
        "plaintext": plaintext,
        "Shannon_encode": r,
        "Hamming": hammming,
        "error": test,
        "corrected": correction,
        "decodedHamming": decoded_hamming,
        "var": var,
        "Decoded": decodedFill,
        "ratio": ratio
    })
