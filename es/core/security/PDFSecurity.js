import CryptoJS from 'crypto-js';
import saslprep from 'saslprep';
/*
Represent the entire security class for the PDF Document
Output from `_setupEncryption` is the Encryption Dictionary
in compliance to the PDF Specification
*/
var PDFSecurity = /** @class */ (function () {
    function PDFSecurity(document, options) {
        if (options === void 0) { options = {}; }
        if (!options.ownerPassword && !options.userPassword) {
            throw new Error('None of owner password and user password is defined.');
        }
        this.document = document;
        this._setupEncryption(options);
    }
    /*
    ID file is an array of two byte-string constituing
    a file identifier
  
    Required if Encrypt entry is present in Trailer
    Doesn't really matter what it is as long as it is
    consistently used.
    */
    PDFSecurity.generateFileID = function (info) {
        return wordArrayToBuffer(CryptoJS.MD5(info.toString()));
    };
    PDFSecurity.generateRandomWordArray = function (bytes) {
        return CryptoJS.lib.WordArray.random(bytes);
    };
    PDFSecurity.create = function (document, options) {
        if (options === void 0) { options = {}; }
        return new PDFSecurity(document, options);
    };
    /*
    Handle all encryption process and give back
    EncryptionDictionary that is required
    to be plugged into Trailer of the PDF
    */
    PDFSecurity.prototype._setupEncryption = function (options) {
        switch (options.pdfVersion) {
            case '1.4':
            case '1.5':
                this.version = 2;
                break;
            case '1.6':
            case '1.7':
                this.version = 4;
                break;
            case '1.7ext3':
                this.version = 5;
                break;
            default:
                this.version = 1;
                break;
        }
        switch (this.version) {
            case 1:
            case 2:
            case 4:
                this.dictionary = this._setupEncryptionV1V2V4(this.version, options);
                break;
            case 5:
                this.dictionary = this._setupEncryptionV5(options);
                break;
        }
    };
    PDFSecurity.prototype._setupEncryptionV1V2V4 = function (v, options) {
        var encDict = {
            Filter: 'Standard',
        };
        var r;
        var permissions;
        switch (v) {
            case 1:
                r = 2;
                this.keyBits = 40;
                permissions = getPermissionsR2(options.permissions);
                break;
            case 2:
                r = 3;
                this.keyBits = 128;
                permissions = getPermissionsR3(options.permissions);
                break;
            case 4:
                r = 4;
                this.keyBits = 128;
                permissions = getPermissionsR3(options.permissions);
                break;
            default:
                throw new Error('Unknown v value');
        }
        var paddedUserPassword = processPasswordR2R3R4(options.userPassword);
        var paddedOwnerPassword = options.ownerPassword
            ? processPasswordR2R3R4(options.ownerPassword)
            : paddedUserPassword;
        var ownerPasswordEntry = getOwnerPasswordR2R3R4(r, this.keyBits, paddedUserPassword, paddedOwnerPassword);
        this.encryptionKey = getEncryptionKeyR2R3R4(r, this.keyBits, this.document._id, paddedUserPassword, ownerPasswordEntry, permissions);
        var userPasswordEntry;
        if (r === 2) {
            userPasswordEntry = getUserPasswordR2(this.encryptionKey);
        }
        else {
            userPasswordEntry = getUserPasswordR3R4(this.document._id, this.encryptionKey);
        }
        encDict.V = v;
        if (v >= 2) {
            encDict.Length = this.keyBits;
        }
        if (v === 4) {
            encDict.CF = {
                StdCF: {
                    AuthEvent: 'DocOpen',
                    CFM: 'AESV2',
                    Length: this.keyBits / 8,
                },
            };
            encDict.StmF = 'StdCF';
            encDict.StrF = 'StdCF';
        }
        encDict.R = r;
        encDict.O = wordArrayToBuffer(ownerPasswordEntry);
        encDict.U = wordArrayToBuffer(userPasswordEntry);
        encDict.P = permissions;
        return encDict;
    };
    PDFSecurity.prototype._setupEncryptionV5 = function (options) {
        var encDict = {
            Filter: 'Standard',
        };
        this.keyBits = 256;
        var permissions = getPermissionsR3(options.permissions);
        var processedUserPassword = processPasswordR5(options.userPassword);
        var processedOwnerPassword = options.ownerPassword
            ? processPasswordR5(options.ownerPassword)
            : processedUserPassword;
        this.encryptionKey = getEncryptionKeyR5(PDFSecurity.generateRandomWordArray);
        var userPasswordEntry = getUserPasswordR5(processedUserPassword, PDFSecurity.generateRandomWordArray);
        var userKeySalt = CryptoJS.lib.WordArray.create(userPasswordEntry.words.slice(10, 12), 8);
        var userEncryptionKeyEntry = getUserEncryptionKeyR5(processedUserPassword, userKeySalt, this.encryptionKey);
        var ownerPasswordEntry = getOwnerPasswordR5(processedOwnerPassword, userPasswordEntry, PDFSecurity.generateRandomWordArray);
        var ownerKeySalt = CryptoJS.lib.WordArray.create(ownerPasswordEntry.words.slice(10, 12), 8);
        var ownerEncryptionKeyEntry = getOwnerEncryptionKeyR5(processedOwnerPassword, ownerKeySalt, userPasswordEntry, this.encryptionKey);
        var permsEntry = getEncryptedPermissionsR5(permissions, this.encryptionKey, PDFSecurity.generateRandomWordArray);
        encDict.V = 5;
        encDict.Length = this.keyBits;
        encDict.CF = {
            StdCF: {
                AuthEvent: 'DocOpen',
                CFM: 'AESV3',
                Length: this.keyBits / 8,
            },
        };
        encDict.StmF = 'StdCF';
        encDict.StrF = 'StdCF';
        encDict.R = 5;
        encDict.O = wordArrayToBuffer(ownerPasswordEntry);
        encDict.OE = wordArrayToBuffer(ownerEncryptionKeyEntry);
        encDict.U = wordArrayToBuffer(userPasswordEntry);
        encDict.UE = wordArrayToBuffer(userEncryptionKeyEntry);
        encDict.P = permissions;
        encDict.Perms = wordArrayToBuffer(permsEntry);
        return encDict;
    };
    PDFSecurity.prototype.getEncryptFn = function (obj, gen) {
        var digest;
        var key;
        if (this.version < 5) {
            digest = this.encryptionKey
                .clone()
                .concat(CryptoJS.lib.WordArray.create([
                ((obj & 0xff) << 24) |
                    ((obj & 0xff00) << 8) |
                    ((obj >> 8) & 0xff00) |
                    (gen & 0xff),
                (gen & 0xff00) << 16,
            ], 5));
            if (this.version === 1 || this.version === 2) {
                key = CryptoJS.MD5(digest);
                key.sigBytes = Math.min(16, this.keyBits / 8 + 5);
                return function (buffer) {
                    return wordArrayToBuffer(CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(buffer), key).ciphertext);
                };
            }
            if (this.version === 4) {
                key = CryptoJS.MD5(digest.concat(CryptoJS.lib.WordArray.create([0x73416c54], 4)));
            }
        }
        else if (this.version === 5) {
            key = this.encryptionKey;
        }
        else {
            throw new Error('Unknown V value');
        }
        var iv = PDFSecurity.generateRandomWordArray(16);
        var options = {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: iv,
        };
        return function (buffer) {
            return wordArrayToBuffer(iv
                .clone()
                .concat(CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(buffer), key, options).ciphertext));
        };
    };
    return PDFSecurity;
}());
/**
 * Get Permission Flag for use Encryption Dictionary (Key: P)
 * For Security Handler revision 2
 *
 * Only bit position 3,4,5,6,9,10,11 and 12 is meaningful
 * Refer Table 22 - User access permission
 * @param  {permissionObject} {@link UserPermission}
 * @returns number - Representing unsigned 32-bit integer
 */
var getPermissionsR2 = function (permissionObject) {
    if (permissionObject === void 0) { permissionObject = {}; }
    var permissions = 0xffffffc0 >> 0;
    if (permissionObject.printing) {
        permissions |= 4;
    }
    if (permissionObject.modifying) {
        permissions |= 8;
    }
    if (permissionObject.copying) {
        permissions |= 16;
    }
    if (permissionObject.annotating) {
        permissions |= 32;
    }
    return permissions;
};
/**
 * Get Permission Flag for use Encryption Dictionary (Key: P)
 * For Security Handler revision 2
 *
 * Only bit position 3,4,5,6,9,10,11 and 12 is meaningful
 * Refer Table 22 - User access permission
 * @param  {permissionObject} {@link UserPermission}
 * @returns number - Representing unsigned 32-bit integer
 */
var getPermissionsR3 = function (permissionObject) {
    if (permissionObject === void 0) { permissionObject = {}; }
    var permissions = 0xfffff0c0 >> 0;
    if (permissionObject.printing === 'lowResolution' ||
        permissionObject.printing) {
        permissions |= 4;
    }
    if (permissionObject.printing === 'highResolution') {
        permissions |= 2052;
    }
    if (permissionObject.modifying) {
        permissions |= 8;
    }
    if (permissionObject.copying) {
        permissions |= 16;
    }
    if (permissionObject.annotating) {
        permissions |= 32;
    }
    if (permissionObject.fillingForms) {
        permissions |= 256;
    }
    if (permissionObject.contentAccessibility) {
        permissions |= 512;
    }
    if (permissionObject.documentAssembly) {
        permissions |= 1024;
    }
    return permissions;
};
var getUserPasswordR2 = function (encryptionKey) {
    return CryptoJS.RC4.encrypt(processPasswordR2R3R4(), encryptionKey).ciphertext;
};
var getUserPasswordR3R4 = function (documentId, encryptionKey) {
    var key = encryptionKey.clone();
    var cipher = CryptoJS.MD5(processPasswordR2R3R4().concat(CryptoJS.lib.WordArray.create(documentId)));
    for (var i = 0; i < 20; i++) {
        var xorRound = Math.ceil(key.sigBytes / 4);
        for (var j = 0; j < xorRound; j++) {
            key.words[j] =
                encryptionKey.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24));
        }
        cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
    }
    return cipher.concat(CryptoJS.lib.WordArray.create(null, 16));
};
var getOwnerPasswordR2R3R4 = function (r, keyBits, paddedUserPassword, paddedOwnerPassword) {
    var digest = paddedOwnerPassword;
    var round = r >= 3 ? 51 : 1;
    for (var i = 0; i < round; i++) {
        digest = CryptoJS.MD5(digest);
    }
    var key = digest.clone();
    key.sigBytes = keyBits / 8;
    var cipher = paddedUserPassword;
    round = r >= 3 ? 20 : 1;
    for (var i = 0; i < round; i++) {
        var xorRound = Math.ceil(key.sigBytes / 4);
        for (var j = 0; j < xorRound; j++) {
            key.words[j] = digest.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24));
        }
        cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
    }
    return cipher;
};
var getEncryptionKeyR2R3R4 = function (r, keyBits, documentId, paddedUserPassword, ownerPasswordEntry, permissions) {
    var key = paddedUserPassword
        .clone()
        .concat(ownerPasswordEntry)
        .concat(CryptoJS.lib.WordArray.create([lsbFirstWord(permissions)], 4))
        .concat(CryptoJS.lib.WordArray.create(documentId));
    var round = r >= 3 ? 51 : 1;
    for (var i = 0; i < round; i++) {
        key = CryptoJS.MD5(key);
        key.sigBytes = keyBits / 8;
    }
    return key;
};
var getUserPasswordR5 = function (processedUserPassword, generateRandomWordArray) {
    var validationSalt = generateRandomWordArray(8);
    var keySalt = generateRandomWordArray(8);
    return CryptoJS.SHA256(processedUserPassword.clone().concat(validationSalt))
        .concat(validationSalt)
        .concat(keySalt);
};
var getUserEncryptionKeyR5 = function (processedUserPassword, userKeySalt, encryptionKey) {
    var key = CryptoJS.SHA256(processedUserPassword.clone().concat(userKeySalt));
    var options = {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
        iv: CryptoJS.lib.WordArray.create(null, 16),
    };
    return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
var getOwnerPasswordR5 = function (processedOwnerPassword, userPasswordEntry, generateRandomWordArray) {
    var validationSalt = generateRandomWordArray(8);
    var keySalt = generateRandomWordArray(8);
    return CryptoJS.SHA256(processedOwnerPassword
        .clone()
        .concat(validationSalt)
        .concat(userPasswordEntry))
        .concat(validationSalt)
        .concat(keySalt);
};
var getOwnerEncryptionKeyR5 = function (processedOwnerPassword, ownerKeySalt, userPasswordEntry, encryptionKey) {
    var key = CryptoJS.SHA256(processedOwnerPassword
        .clone()
        .concat(ownerKeySalt)
        .concat(userPasswordEntry));
    var options = {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
        iv: CryptoJS.lib.WordArray.create(null, 16),
    };
    return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext;
};
var getEncryptionKeyR5 = function (generateRandomWordArray) { return generateRandomWordArray(32); };
var getEncryptedPermissionsR5 = function (permissions, encryptionKey, generateRandomWordArray) {
    var cipher = CryptoJS.lib.WordArray.create([lsbFirstWord(permissions), 0xffffffff, 0x54616462], 12).concat(generateRandomWordArray(4));
    var options = {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.NoPadding,
    };
    return CryptoJS.AES.encrypt(cipher, encryptionKey, options).ciphertext;
};
var processPasswordR2R3R4 = function (password) {
    if (password === void 0) { password = ''; }
    var out = Buffer.alloc(32);
    var length = password.length;
    var index = 0;
    while (index < length && index < 32) {
        var code = password.charCodeAt(index);
        if (code > 0xff) {
            throw new Error('Password contains one or more invalid characters.');
        }
        out[index] = code;
        index++;
    }
    while (index < 32) {
        out[index] = PASSWORD_PADDING[index - length];
        index++;
    }
    return CryptoJS.lib.WordArray.create(out);
};
var processPasswordR5 = function (password) {
    if (password === void 0) { password = ''; }
    password = unescape(encodeURIComponent(saslprep(password)));
    var length = Math.min(127, password.length);
    var out = Buffer.alloc(length);
    for (var i = 0; i < length; i++) {
        out[i] = password.charCodeAt(i);
    }
    return CryptoJS.lib.WordArray.create(out);
};
var lsbFirstWord = function (data) {
    return ((data & 0xff) << 24) |
        ((data & 0xff00) << 8) |
        ((data >> 8) & 0xff00) |
        ((data >> 24) & 0xff);
};
var wordArrayToBuffer = function (wordArray) {
    var byteArray = [];
    for (var i = 0; i < wordArray.sigBytes; i++) {
        byteArray.push((wordArray.words[Math.floor(i / 4)] >> (8 * (3 - (i % 4)))) & 0xff);
    }
    return Uint8Array.from(byteArray);
};
/*
  7.6.3.3 Encryption Key Algorithm
  Algorithm 2
  Password Padding to pad or truncate
  the password to exactly 32 bytes
*/
var PASSWORD_PADDING = [
    0x28,
    0xbf,
    0x4e,
    0x5e,
    0x4e,
    0x75,
    0x8a,
    0x41,
    0x64,
    0x00,
    0x4e,
    0x56,
    0xff,
    0xfa,
    0x01,
    0x08,
    0x2e,
    0x2e,
    0x00,
    0xb6,
    0xd0,
    0x68,
    0x3e,
    0x80,
    0x2f,
    0x0c,
    0xa9,
    0xfe,
    0x64,
    0x53,
    0x69,
    0x7a,
];
export default PDFSecurity;
//# sourceMappingURL=PDFSecurity.js.map