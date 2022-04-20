import math
import struct
import base64
import sqlite3
from unicodedata import name
import xml.etree.ElementTree as ET

def unpack_user(struct_en):

    file = open("userconfing.xml","r")
    root = ET.parse(file).getroot()
    elem = root.find('.//string[@name="user"]')
    struct_en = elem.text.partition('\n')[0]

    struct_de = base64.b64decode(struct_en)

    # Get structure constructor, so we know we are decoding right data
    constructor = struct.unpack('<L', struct_de[:4])[0]

    if constructor != int('0x3ff6ecb0', 16):
        print('Unknown constructor for user structure. Format of data probably changed.')
        return

    # Get flags, so we know which attributes are provided
    flags = struct.unpack('<L', struct_de[4:8])[0]
    name_bool = (flags & 2) != 0
    surname_bool = (flags & 4) != 0
    username_bool = (flags & 8) != 0
    phone_bool = (flags & 16) != 0

    bot = (flags & 16384) != 0
    verified = (flags & 131072) != 0
    restricted = (flags & 262144) != 0
    scam = (flags & 16777216) != 0
    fake = (flags & 67108864) != 0

    struct_de = struct_de[8:]

    #print(int.from_bytes(struct_de[8:16], 'little'))
    user_id = struct.unpack('<Q', struct_de[:8])[0]
    print('ID: ', user_id)
    struct_de = struct_de[16:]

    if name_bool and surname_bool:
        name_len = struct_de[0]
        name = struct_de[1:1+name_len].decode('utf-8')
        # Calculating lenght with padding, becasue lenght of the string has to
        # be divisible by 4
        len_with_padding = math.ceil((name_len+1)/4)*4
        struct_de = struct_de[len_with_padding:]
        print('Name: ', name)

    if surname_bool:
        surname_len = struct_de[0]
        surname = struct_de[1:1+surname_len].decode('utf-8')
        len_with_padding = math.ceil((surname_len+1)/4)*4
        struct_de = struct_de[len_with_padding:]
        print('Surname: ', surname)

    if username_bool:
        username_len = struct_de[0]
        username = struct_de[1:1+username_len].decode('utf-8')
        len_with_padding = math.ceil((username_len+1)/4)*4
        struct_de = struct_de[len_with_padding:]
        print('Username: ', username)

    if phone_bool:
        phone_len = struct_de[0]
        phone = struct_de[1:1+phone_len].decode('utf-8')
        len_with_padding = math.ceil((phone_len+1)/4)*4
        struct_de = struct_de[len_with_padding:]
        print('Phone: ', phone)

def get_contacts():
    con = sqlite3.connect('cache4.db')
    cur = con.cursor()
    print('Names of telegram contacts:')
    for row in cur.execute('SELECT * FROM users WHERE uid IN (SELECT uid FROM contacts)'):
        print(row[1])

def main():
    unpack_user(struct_en)
    get_contacts()

if __name__ == '__main__':  
    main()