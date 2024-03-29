const base58check=require('base58check');
const {bech32}=require('bech32');
const nacl=require('tweetnacl');

const digibyte= /** @type {CryptoNetwork} */{
    messagePrefix: '\x19DigiByte Signed Message:\\n',
    bech32: 'dgb',
    bip32: {
        public: 0x049d7cb2,
        private: 0x049d7878,
    },
    pubKeyHash: 0x1e,
    scriptHash: 0x3f,
    wif: 0x80,
};

const ChatSet3B40="0123456789abcdefghijklmnopqrstuvwxyz#$&.";
const ChatSetAlpha="0123456789abcdefghijklmnopqrstuvwxyz $%*+-./:";
const isBinary=/^[01]+$/;
const isHex = /^[0-9a-fA-F]+$/;
const bitcoinOpCodes= {
    OP_0:           0,
    OP_FALSE:       0,
    OP_PUSHDATA1:   76,
    OP_PUSHDATA2:   77,
    OP_PUSHDATA4:   78,
    OP_1NEGATE:     79,
    OP_1:           80,
    OP_TRUE:        81,
    OP_2:           82,
    OP_3:           83,
    OP_4:           84,
    OP_5:           85,
    OP_6:           86,
    OP_7:           87,
    OP_8:           88,
    OP_9:           89,
    OP_10:          90,
    OP_11:          91,
    OP_12:          92,
    OP_13:          93,
    OP_14:          94,
    OP_15:          95,
    OP_16:          96,
    OP_NOP:         97,
    OP_IF:          99,
    OP_NOTIF:       100,
    OP_ELSE:        103,
    OP_ENDIF:       104,
    OP_VERIFY:      105,
    OP_RETURN:      106,
    OP_TOALTSTACK:  107,
    OP_FROMALTSTACK:108,
    OP_IFDUP:       115,
    OP_DEPTH:       116,
    OP_DROP:        117,
    OP_DUP:         118,
    OP_NIP:         119,
    OP_OVER:        120,
    OP_PICK:        121,
    OP_ROLL:        122,
    OP_ROT:         123,
    OP_SWAP:        124,
    OP_TUCK:        125,
    OP_2DROP:       109,
    OP_2DUP:        110,
    OP_3DUP:        111,
    OP_2OVER:       112,
    OP_2ROT:        113,
    OP_2SWAP:       114,
    OP_SIZE:        130,
    OP_EQUAL:       135,
    OP_EQUALVERIFY: 136,
    OP_1ADD:        139,
    OP_1SUB:        140,
    OP_NEGATE:      143,
    OP_ABS:         144,
    OP_NOT:         145,
    OP_0NOTEQUAL:   146,
    OP_ADD:         147,
    OP_SUB:         148,
    OP_BOOLAND:     154,
    OP_BOOLOR:      155,
    OP_NUMEQUAL:    156,
    OP_NUMEQUALVERIFY:      157,
    OP_NUMNOTEQUAL: 158,
    OP_LESSTHAN:    159,
    OP_GREATERTHAN: 160,
    OP_LESSTHANOREQUAL:     161,
    OP_GREATERTHANOREQUAL:  162,
    OP_MIN:         163,
    OP_MAX:         164,
    OP_WITHIN:      165,
    OP_RIPEMD160:   166,
    OP_SHA1:        167,
    OP_SHA256:      168,
    OP_HASH160:             169,
    OP_HASH256:             170,
    OP_CODESEPARATOR:       171,
    OP_CHECKSIG:            172,
    OP_CHECKSIGVERIFY:      173,
    OP_CHECKMULTISIG:       174,
    OP_CHECKMULTISIGVERIFY: 175,
    OP_CHECKLOCKTIMEVERIFY: 177,
    OP_CHECKSEQUENCEVERIFY: 178,
};


/**
 * @type {{
    messagePrefix:  string,
    bech32:         string,
    bip32: {
        public:     int,
        private:    int,
    },
    pubKeyHash:     int,
    scriptHash:     int,
    wif:            int,
}}
 */
let CryptoNetwork;

/*
    Commands:
        get:    gets data from the current pointer and moves pointer
        insert: inserts data at the current pointer and moves pointer to end of new data
        append: appends data to the end.  Does NOT move pointer


    Encoding formats requiring length:
        Bits:               string of "1" and "0"
        Int:                integer number from 0 to 2^length-1
        Alpha:              encodes a string using QR code alphanumeric encoding(uses lower case though)
        UTF8:               encodes a string using a modified version of UTF8.  Same except redundant bits have been
                            removed
        Hex:                encodes a string made up of hexadecimal characters
        3B40:               designed for file extensions.  efficiently encodes strings made of only
                            0123456789abcdefghijklmnopqrstuvwxyz#$&. characters


    Encoding formats not requiring length value:
        XBitVariableLength: string of "1" and "0" but with no fixed length.  Bits are taken X bits at a time until at
                            least 1 bit is "1"
        Address:            encodes a string containing a DigiByte address
        FixedPrecision:     encodes a number using bitcoins fixed precision encoding

 */





class BitIO {
    constructor() {
        this._bits='';
        this._pointer=0;
    }

    /**
     * Moves pointer by amount
     * @param {int} amount
     */
    movePointer(amount) {
        let newPoint=this._pointer+amount;
        if ((newPoint<0)||(newPoint>this._bits.length)) throw new Error("Pointer moved out of range");
        this._pointer=newPoint;
    }

    /**
     * Moves pointer to location
     * @param {int} location
     */
    set pointer(location) {
        if ((location<0)||(location>this._bits.length)) throw new Error("Pointer moved out of range");
        this._pointer=location;
    }

    /**
     * Gets location of pointer
     * @return {int}
     */
    get pointer() {
        return this._pointer;
    }

    /**
     * Gets the number of bits
     * @return {int}
     */
    get length() {
        return this._bits.length;
    }

    /**
     * Gets the number of bits remaining
     * @return {int}
     */
    get remaining() {
        return (this.length-this._pointer);
    }

    /**
     * Pads the data to be a multiple of multiple bits past current pointer
     * @param {int} multiple
     */
    padZero(multiple) {
        let needed=multiple-(this.remaining%multiple);
        if (needed===multiple) return;      //if already correct length
        this.appendBits("".padStart(needed,'0'));
    }

    /**
     * Pads the data to be a multiple of multiple bits past current pointer
     * @param {int} multiple
     */
    padOne(multiple) {
        let needed=multiple-(this.remaining%multiple);
        if (needed===multiple) return;      //if already correct length
        this.appendBits("".padStart(needed,'0'));
    }


    /**
     * Pads the data to be a multiple of multiple bits past current pointer
     * @param multiple
     */
    padRandom(multiple) {
        let needed=multiple-(this.remaining%multiple);
        if (needed===multiple) return;      //if already correct length
        let bits="";
        for (let i=0;i<needed;i++) {
            bits+=Math.floor(Math.random()*2).toString();
        }
        this.appendBits(bits);
    }

    /**
     * Converts to buffer.  Must be multiple of 8 bits
     * @return {Buffer}
     */
    toBuffer() {
        let byteCount=this._bits.length/8;
        if (this._bits.length%8!==0) throw new Error("Must be multiple 8 bits to convert to buffer");
        let data=Buffer.alloc(byteCount);
        for (let i=0;i<byteCount;i++) data[i]=parseInt(this._bits.substr(i*8,8),2);
        return data;
    }

    /**
     *
     * @param data
     * @return {BitIO}
     */
    static fromBuffer(data) {
        let temp=new BitIO();
        temp.appendBuffer(data);
        return temp;
    }


    /*
    ███████╗████████╗██████╗ ██╗███╗   ██╗ ██████╗ ███████╗
    ██╔════╝╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝
    ███████╗   ██║   ██████╔╝██║██╔██╗ ██║██║  ███╗███████╗
    ╚════██║   ██║   ██╔══██╗██║██║╚██╗██║██║   ██║╚════██║
    ███████║   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝███████║
    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
     */


    /**
     * Finds best encoding method of types given.  Works only if desired format is
     * {header}{length fixed bit count}{bits}
     * options key should be the header
     * @param {string}  message
     * @param {int}     lengthBits
     * @param {Object<string>}options
     * @return {string}
     */
    static makeBestString(message,lengthBits,options) {
        //list of encoding options
        const encoders={
            "Alpha":    BitIO.makeAlpha,
            "UTF8":     BitIO.makeUTF8,
            "Hex":      BitIO.makeHex,
            "3B40":     BitIO.make3B40
        }

        //compute length value
        if (message.length>=Math.pow(2,lengthBits)) throw new Error("Max Length Exceeded")
        const binLength=message.length.toString(2).padStart(lengthBits,'0');

        //find best value
        let minLength=Infinity,binary;
        for (let header in options) {
            //get encoder
            // noinspection JSUnfilteredForInLoop
            let encoder=encoders[options[header]];
            if (encoder===undefined) throw new Error("Unknown Encoder");

            //try encoding and record if better then existing options
            try {
                let binaryOption = header+binLength+encoder(message);
                if (binaryOption.length<minLength) {    //see if smaller then existing
                    minLength=binaryOption.length;      //record size
                    binary=binaryOption;                //record binary string
                }
            } catch (_) {}
        }

        //return if any results found
        if (binary===undefined) throw new Error("Invalid Input Type");
        return binary;
    }

    /**
     * Insert string at end
     * DOES NOT EFFECT POINTER
     * @param {string} message
     * @param {int}     lengthBits
     * @param {Object<string>}options
     */
    appendBestString(message,lengthBits,options) {
        this.appendBits(BitIO.makeBestString(message,lengthBits,options));
    }

    /**
     * Insert string wherever pointer is
     * @param {string} message
     * @param {int}     lengthBits
     * @param {Object<string>}options
     * @param {boolean} updatePointer
     */
    insertBestString(message,lengthBits,options,updatePointer=true) {
        this.insertBits(BitIO.makeBestString(message,lengthBits,options),updatePointer);
    }





    /*
    ██████╗ ██╗████████╗███████╗
    ██╔══██╗██║╚══██╔══╝██╔════╝
    ██████╔╝██║   ██║   ███████╗
    ██╔══██╗██║   ██║   ╚════██║
    ██████╔╝██║   ██║   ███████║
    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
     */

    /**
     * Gets bits from data and updates pointer
     * @param {int} length
     * @return {string}
     */
    getBits(length) {
        //check the bits exist
        if (this._bits.length<this._pointer+length) throw new Error("not enough bits left");

        //get the bits and move pointer
        let value=this._bits.substr(this._pointer,length);
        this._pointer+=length;

        return value;
    }

    /**
     * Insert bits at end.  value should be a string of 1 and 0 only
     * DOES NOT EFFECT POINTER
     * @param {string}  value
     */
    appendBits(value) {
        if (!isBinary.test(value)) throw new Error("Invalid Input Type");    //throw error if can't be included
        this._bits+=value;
    }

    /**
     * Insert bits wherever pointer is
     * value should be a string of 1 and 0 only
     * @param {string}  value
     * @param {boolean} updatePointer
     */
    insertBits(value,updatePointer=true) {
        if (!isBinary.test(value)) throw new Error("Invalid Input Type");    //throw error if can't be included
        this._bits=this._bits.substr(0,this._pointer)+value+this._bits.substr(this._pointer);
        if (updatePointer) this._pointer+=value.length;
    }

    /**
     * Checks if next bits match a binary string.
     * DOES NOT UPDATE POINTER
     * @param {string}  check
     * @return {boolean}
     */
    checkBits(check) {
        return (this._bits.substr(this._pointer,check.length)===check);
    }



    /*
    ██████╗ ██╗   ██╗███████╗███████╗███████╗██████╗
    ██╔══██╗██║   ██║██╔════╝██╔════╝██╔════╝██╔══██╗
    ██████╔╝██║   ██║█████╗  █████╗  █████╗  ██████╔╝
    ██╔══██╗██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝██║     ██║     ███████╗██║  ██║
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
     */

    /**
     * Gets a buffer length bytes long
     * @param {int} length
     * @return {Buffer}
     */
    getBuffer(length) {
        let data=Buffer.alloc(length);
        for (let i=0;i<length;i++) data[i]=this.getInt(8);
        return data;
    }

    /**
     * Converts a buffer to binary string
     * @param {Buffer}  data
     * @return {string}
     */
    static makeBuffer(data) {
        let binary="";
        for (let i=0;i<data.length;i++) binary+=data[i].toString(2).padStart(8,'0');
        return binary;
    }

    /**
     * Put buffer at end
     * DOES NOT EFFECT POINTER
     * @param {Buffer} data
     */
    appendBuffer(data) {
        this.appendBits(BitIO.makeBuffer(data));
    }

    /**
     *  Insert buffer at pointer
     * @param {Buffer} data
     * @param {boolean} updatePointer
     */
    insertBuffer(data,updatePointer=true) {
        this.insertBits(BitIO.makeBuffer(data),updatePointer);
    }



    /*
    ██╗   ██╗ █████╗ ██████╗ ██╗ █████╗ ██████╗ ██╗     ███████╗    ██╗     ███████╗███╗   ██╗ ██████╗████████╗██╗  ██╗
    ██║   ██║██╔══██╗██╔══██╗██║██╔══██╗██╔══██╗██║     ██╔════╝    ██║     ██╔════╝████╗  ██║██╔════╝╚══██╔══╝██║  ██║
    ██║   ██║███████║██████╔╝██║███████║██████╔╝██║     █████╗      ██║     █████╗  ██╔██╗ ██║██║  ███╗  ██║   ███████║
    ╚██╗ ██╔╝██╔══██║██╔══██╗██║██╔══██║██╔══██╗██║     ██╔══╝      ██║     ██╔══╝  ██║╚██╗██║██║   ██║  ██║   ██╔══██║
     ╚████╔╝ ██║  ██║██║  ██║██║██║  ██║██████╔╝███████╗███████╗    ███████╗███████╗██║ ╚████║╚██████╔╝  ██║   ██║  ██║
      ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
     */

    /**
     * Returns value and updates pointer.
     * In this encoding scheme we take x bits at a time if not all are 0 we stop.  If they are we repeat
     * @param {int}  x
     * @return {string}
     */
    getXBitVariableLength(x) {
        let bits="";
        while (parseInt(bits+"0",2)===0) {
            bits+=this.getBits(x);
        }
        return bits;
    }

    /**
     * Error check bits
     * @param {string}  value
     * @param {int}     x
     */
    static makeXBitVariableLength(value,x) {
        if (
            (value.length%x!==0)||
            (!isBinary.test(value))||
            (parseInt("0"+value.substr(0,value.length-x),2)!==0)
        ) throw new Error("Invalid Input Type");    //throw error if can't be included
        return value;
    }

    /**
     * Insert variable bit value.  Input must be string of 0 & 1 at end
     * DOES NOT EFFECT POINTER
     * @param {string} value
     * @param {int} x
     */
    appendXBitVariableLength(value,x) {
        this.appendBits(BitIO.makeXBitVariableLength(value,x));
    }

    /**
     *  Insert variable bit value.  Input must be string of 0 & 1 wherever pointer is
     * @param {string} value
     * @param {int} x
     * @param {boolean} updatePointer
     */
    insertXBitVariableLength(value,x,updatePointer=true) {
        this.insertBits(BitIO.makeXBitVariableLength(value,x),updatePointer);
    }

    /*
    ██████╗ ██╗ ██████╗ ██╗███╗   ██╗████████╗
    ██╔══██╗██║██╔════╝ ██║████╗  ██║╚══██╔══╝
    ██████╔╝██║██║  ███╗██║██╔██╗ ██║   ██║
    ██╔══██╗██║██║   ██║██║██║╚██╗██║   ██║
    ██████╔╝██║╚██████╔╝██║██║ ╚████║   ██║
    ╚═════╝ ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝
     */

    /**
     * Returns unsigned int of bits length.  Warning 31 bit max
     * @param {int} length
     * @return {BigInt}
     */
    getBigInt(length) {
        return BigInt("0b"+this.getBits(length));
    }

    /**
     * Returns binary for an integer
     * @param {BigInt} value
     * @param {int} length
     * @return {string}
     */
    static makeBigInt(value,length) {
        if (typeof value ==="bigint") throw new Error("Invalid Input Type");    //throw error if can't be included
        if (value>=Math.pow(2,length)) throw new Error("Length to short to encode");
        // noinspection JSCheckFunctionSignatures
        return value.toString(2).padStart(length,'0');
    }

    /**
     * Insert integer at end
     * DOES NOT EFFECT POINTER
     * @param {BigInt} value
     * @param {int} length
     */
    appendBigInt(value,length) {
        this.appendBits(BitIO.makeBigInt(value,length));
    }

    /**
     * Insert integer wherever pointer is
     * @param {BigInt} value
     * @param {int} length
     * @param {boolean} updatePointer
     */
    insertBigInt(value,length,updatePointer=true) {
        this.insertBits(BitIO.makeBigInt(value,length),updatePointer);
    }

    /*
    ██╗███╗   ██╗████████╗███████╗ ██████╗ ███████╗██████╗
    ██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔════╝██╔══██╗
    ██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗█████╗  ██████╔╝
    ██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══╝  ██╔══██╗
    ██║██║ ╚████║   ██║   ███████╗╚██████╔╝███████╗██║  ██║
    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
     */

    /**
     * Returns unsigned int of bits length.  Warning 31 bit max
     * @param {int} length
     * @return {int}
     */
    getInt(length) {
        if (length>31) throw new Error("Max Length Exceeded");
        return parseInt(this.getBits(length),2);
    }

    /**
     * Returns binary for an integer
     * @param {int} value
     * @param {int} length
     * @return {string}
     */
    static makeInt(value,length) {
        if ((value < 0) || (value!==Math.min(value))) throw new Error("Invalid Input Type");    //throw error if can't be included
        if (value>=Math.pow(2,length)) throw new Error("Length to short to encode");
        // noinspection JSCheckFunctionSignatures
        return value.toString(2).padStart(length,'0');
    }

    /**
     * Insert integer at end
     * DOES NOT EFFECT POINTER
     * @param {int} value
     * @param {int} length
     */
    appendInt(value,length) {
        this.appendBits(BitIO.makeInt(value,length));
    }

    /**
     * Insert integer wherever pointer is
     * @param {int} value
     * @param {int} length
     * @param {boolean} updatePointer
     */
    insertInt(value,length,updatePointer=true) {
        this.insertBits(BitIO.makeInt(value,length),updatePointer);
    }


    /*
     █████╗ ██╗     ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗   ██╗███╗   ███╗███████╗██████╗ ██╗ ██████╗
    ██╔══██╗██║     ██╔══██╗██║  ██║██╔══██╗████╗  ██║██║   ██║████╗ ████║██╔════╝██╔══██╗██║██╔════╝
    ███████║██║     ██████╔╝███████║███████║██╔██╗ ██║██║   ██║██╔████╔██║█████╗  ██████╔╝██║██║
    ██╔══██║██║     ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  ██╔══██╗██║██║
    ██║  ██║███████╗██║     ██║  ██║██║  ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗██║  ██║██║╚██████╗
    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝
     */
    /**
     * Gets a string from data encoded using QR Codes Alphanumeric coding
     * @param {int} length
     * @return {string}
     */
    getAlpha(length) {
        const charSet=ChatSetAlpha;
        let message="";
        for (let i=0;i<Math.floor(length/2);i++) {
            let chars=this.getInt(11);
            message+=charSet[Math.floor(chars/45)];
            message+=charSet[chars%45];
        }
        if (length%2===1) {
            message+=charSet[this.getInt(6)];
        }
        return message;
    }

    /**
     * Converts message to binary
     * @param {string}  message
     */
    static makeAlpha(message) {
        const charSet=ChatSetAlpha;
        let binary="";
        let val=0;
        for (let i=0;i<message.length;i++) {
            let pos=charSet.indexOf(message[i]);                      //get value for character
            if (pos===-1) throw new Error("Invalid Input Type");    //throw error if can't be included
            val=val*45+pos;

            //record bits if multiple of 3 characters
            if (i%2===1) {
                binary+=val.toString(2).padStart(11,'0');
                val=0;
            }
        }

        //record left over bits
        let remainder=message.length%2;
        if (remainder!==0) binary+=val.toString(2).padStart(6, '0');
        return binary;
    }

    /**
     * Insert string at end
     * DOES NOT EFFECT POINTER
     * @param {string} message
     */
    appendAlpha(message) {
        this.appendBits(BitIO.makeAlpha(message));
    }

    /**
     * Insert string wherever pointer is
     * @param {string} message
     * @param {boolean} updatePointer
     */
    insertAlpha(message,updatePointer=true) {
        this.insertBits(BitIO.makeAlpha(message),updatePointer);
    }



    /*
    ██╗   ██╗████████╗███████╗ █████╗
    ██║   ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║   ██║   ██║   █████╗  ╚█████╔╝
    ██║   ██║   ██║   ██╔══╝  ██╔══██╗
    ╚██████╔╝   ██║   ██║     ╚█████╔╝
     ╚═════╝    ╚═╝   ╚═╝      ╚════╝
     */

    /**
     * Gets a string from data encoded in a modified version of UTF8
     * not true utf8 since there is unneeded bits in utf8 to allow for backwards with ascii
     * so header is:
     * 0:      followed by 7 bits      U+0000 to U+007F
     * 10:     followed by 11 bits     U+0080 to U+07FF
     * 110:    followed by 16 bits     U+0800 to U+FFFF
     * 111:    followed by 21 bits     U+1000 to U+10FFFF
     * @param {int} length
     * @return {string}
     */
    getUTF8(length) {
        let message='';
        for (let i=0;i<length;i++) {
            //decode the code point from the binary stream
            let codePoint=0;
            if (this.getBits(1)==="0") {         //0...
                codePoint=this.getInt(7);
            } else {                              //1...
                if (this.getBits(1)==="0") {     //10...
                    codePoint=this.getInt(11);
                } else {                          //11...
                    if (this.getBits(1)==="0") { //110...
                        codePoint=this.getInt(16);
                    } else {                      //111...
                        codePoint=this.getInt(21);
                    }
                }
            }

            //convert code point to string
            message+=String.fromCodePoint(codePoint);
        }

        return message;
    }

    /**
     * Converts string to modified utf8 binary value
     * nodejs does not seem to handle 4 byte unicode symbols.  But code for it is included if ported to other languages
     * @param {string}  message
     * @return {string}
     */
    static makeUTF8(message) {
        let binary='';
        for (let i=0;i<message.length;i++) {
            //look up the code point for the letter
            let codePoint=message.codePointAt(i);

            //convert to binary
            if (codePoint<128) {
                binary+="0"+codePoint.toString(2).padStart(7,'0');
            } else if (codePoint<2048) {
                binary+="10"+codePoint.toString(2).padStart(11,'0');
            } else if (codePoint<65536) {
                binary+="110"+codePoint.toString(2).padStart(16,'0');
            } else {
                binary+="111"+codePoint.toString(2).padStart(21,'0');
            }
        }

        return binary;
    }

    /**
     * Insert string at end
     * DOES NOT EFFECT POINTER
     * @param {string}  message
     */
    appendUTF8(message) {
        this.appendBits(BitIO.makeUTF8(message));
    }

    /**
     * Insert string wherever pointer is
     * @param {string}  message
     * @param {boolean} updatePointer
     */
    insertUTF8(message,updatePointer=true) {
        this.insertBits(BitIO.makeUTF8(message),updatePointer);
    }


    /*
    ██╗  ██╗███████╗██╗  ██╗
    ██║  ██║██╔════╝╚██╗██╔╝
    ███████║█████╗   ╚███╔╝
    ██╔══██║██╔══╝   ██╔██╗
    ██║  ██║███████╗██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
     */
    /**
     * Gets a hexadecimal string from data
     * if no length value returns remaining full nibbles
     * @param {int|undefined} length
     * @return {string}
     */
    getHex(length=undefined) {
        if (length===undefined) length=Math.floor(this.remaining/4);
        if (length<=0) throw new Error("Invalid length");
        let message='';
        for (let i=0;i<length;i++) {
            // noinspection JSCheckFunctionSignatures
            message+=this.getInt(4).toString(16);
        }
        return message;
    }

    /**
     * Returns binary value for a hex string
     * @param {string}  value
     * @return {string}
     */
    static makeHex(value) {
        if (!isHex.test(value)) throw new Error("Invalid Input Type");    //throw error if can't be included
        let message='';
        for (let i=0;i<value.length;i++) {
            message+=parseInt(value[i],16).toString(2).padStart(4,'0');
        }
        return message;
    }

    /**
     * Insert string at end
     * DOES NOT EFFECT POINTER
     * @param {string}  message
     */
    appendHex(message) {
        this.appendBits(BitIO.makeHex(message));
    }

    /**
     * Insert string wherever pointer is
     * @param {string}  message
     * @param {boolean} updatePointer
     */
    insertHex(message,updatePointer=true) {
        this.insertBits(BitIO.makeHex(message),updatePointer);
    }



    /*
    ██████╗ ██████╗ ██╗  ██╗ ██████╗
    ╚════██╗██╔══██╗██║  ██║██╔═████╗
     █████╔╝██████╔╝███████║██║██╔██║
     ╚═══██╗██╔══██╗╚════██║████╔╝██║
    ██████╔╝██████╔╝     ██║╚██████╔╝
    ╚═════╝ ╚═════╝      ╚═╝ ╚═════╝
     */

    /**
     * special encoding 40 symbols with every 3 characters aligning to 2 bytes
     * if not a multiple of 3 last 1 character use 5bits,
     * if not a multiple of 3 last 2 characters use 11bits
     * can represent symbols: 0123456789abcdefghijklmnopqrstuvwxyz#$&_
     * @param {int} length
     * @return {string}
     */
    get3B40(length) {
        const charSet=ChatSet3B40;
        let message="";
        for (let i=0;i<Math.floor(length/3);i++) {
            let chars=this.getInt(16);
            message+=charSet[Math.floor(chars/1600)];
            chars=chars%1600;
            message+=charSet[Math.floor(chars/40)];
            message+=charSet[chars%40];
        }
        if (length%3===1) message+=charSet[this.getInt(5)];
        if (length%3===2) {
            let chars=this.getInt(11);
            message+=charSet[Math.floor(chars/40)];
            message+=charSet[chars%40];
        }
        return message;
    }

    /**
     * Returns binary from string
     * @param {string}  value
     * @return {string}
     */
    static make3B40(value) {
        const charSet=ChatSet3B40;
        let message="";
        let val=0;
        for (let i=0;i<value.length;i++) {
            let pos=charSet.indexOf(value[i]);                      //get value for character
            if (pos===-1) throw new Error("Invalid Input Type");    //throw error if can't be included
            val=val*40+pos;

            //record bits if multiple of 3 characters
            if (i%3===2) {
                message+=val.toString(2).padStart(16,'0');
                val=0;
            }
        }

        //record left over bits
        let remainder=value.length%3;
        if (remainder!==0) message+=val.toString(2).padStart((remainder===1)?5:11, '0');

        return message;
    }

    /**
     * Insert string at end
     * DOES NOT EFFECT POINTER
     * @param {string}  message
     */
    append3B40(message) {
        this.appendBits(BitIO.make3B40(message));
    }

    /**
     * Insert string wherever pointer is
     * @param {string}  message
     * @param {boolean} updatePointer
     */
    insert3B40(message,updatePointer=true) {
        this.insertBits(BitIO.make3B40(message),updatePointer);
    }


    /*
     █████╗ ██████╗ ██████╗ ██████╗ ███████╗███████╗███████╗
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
    ███████║██║  ██║██║  ██║██████╔╝█████╗  ███████╗███████╗
    ██╔══██║██║  ██║██║  ██║██╔══██╗██╔══╝  ╚════██║╚════██║
    ██║  ██║██████╔╝██████╔╝██║  ██║███████╗███████║███████║
    ╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
     */

    /**
     * Gets address from data stream
     * @param {CryptoNetwork}   network
     * @return {string}
     */
    getAddress(network=digibyte) {
        //get what address type was encoded
        let type=this.getXBitVariableLength(2);

        //get the pubkey hash
        let pubkeyHash=this.getHex(40);

        //calculate the address based on type
        switch (type) {
            case '01':  //D...
                // noinspection JSCheckFunctionSignatures
                return base58check.encode(pubkeyHash,network.pubKeyHash.toString(16));
            case '10':  //S..
                // noinspection JSCheckFunctionSignatures
                return base58check.encode(pubkeyHash,network.scriptHash.toString(16));
            case '11':  //dgb1..
                let words=bech32.toWords(Buffer.from(pubkeyHash,'hex'));
                words.unshift(0);   //add 0 to beginning
                return bech32.encode(network.bech32,words);
        }
        throw new Error("Invalid Input Type");    //throw error if can't be included
    }

    /**
     * Returns binary from DigiByte Address
     * @param {string}  address
     * @param {CryptoNetwork}   network
     * @return {string}
     */
    static makeAddress(address,network=digibyte) {
        //determine address type by length
        if (address.length===34) {              //Base58
            let {/** @type {string} */prefix,/** @type {string} */data} = base58check.decode(address, 'hex');   //decode to hex(typescript reports Buffer returned but string actually returned)
            // noinspection JSCheckFunctionSignatures
            let bits = (prefix === network.pubKeyHash.toString(16).padStart(2,'0')) ? "01" : "10"; //pay to pubkeyhash : pay to script
            return bits + BitIO.makeHex(data);

        } else {                                //bech32
            let {words}=bech32.decode(address);                     //convert address to words
            words.shift();                                          //remove first value which is always 0
            return "11"+BitIO.makeHex(Buffer.from(bech32.fromWords(words)).toString('hex'));
        }
    }

    /**
     * Insert address at end
     * DOES NOT EFFECT POINTER
     * @param {string}  address
     */
    appendAddress(address) {
        this.appendBits(BitIO.makeAddress(address));
    }

    /**
     * Insert address wherever pointer is
     * @param {string}  address
     * @param {boolean} updatePointer
     */
    insertAddress(address,updatePointer=true) {
        this.insertBits(BitIO.makeAddress(address),updatePointer);
    }



    /*
    ███████╗██╗██╗  ██╗███████╗██████╗
    ██╔════╝██║╚██╗██╔╝██╔════╝██╔══██╗
    █████╗  ██║ ╚███╔╝ █████╗  ██║  ██║
    ██╔══╝  ██║ ██╔██╗ ██╔══╝  ██║  ██║
    ██║     ██║██╔╝ ██╗███████╗██████╔╝
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═════╝

    ██████╗ ██████╗ ███████╗ ██████╗██╗███████╗██╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██║██╔═══██╗████╗  ██║
    ██████╔╝██████╔╝█████╗  ██║     ██║███████╗██║██║   ██║██╔██╗ ██║
    ██╔═══╝ ██╔══██╗██╔══╝  ██║     ██║╚════██║██║██║   ██║██║╚██╗██║
    ██║     ██║  ██║███████╗╚██████╗██║███████║██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
     */
    /**
     * Returns a int that was encoded using bitcoins precision encoding
     * valid number range 0-10,000,000,000,000,000
     * @return {BigInt}
     */
    getFixedPrecision() {
        //length encodes first 3 bits
        let length=this.getInt(3)+1;

        //max length is 7 bytes so if 7 or 8 this is part of bit data
        if (length>=7) {
            this._pointer--;
            length=7;
        }

        //split into parts
        let mantissa,exponent=0n;
        if (length===1) {                                           //1 byte number
            mantissa=this.getBigInt(5);
        } else if (length<5) {                                      //2 to 4 byte number
            mantissa=this.getBigInt(length*8-7);
            exponent=this.getBigInt(4);
        } else if (length<7) {                                      //5 to 6 byte number
            mantissa=this.getBigInt(length*8-6);
            exponent=this.getBigInt(3);
        } else {                                                    //7 byte number
            mantissa=this.getBigInt(54);
        }

        //calculate the number and return
        return mantissa*(10n**exponent);
    }

    /**
     * Returns a int that was encoded using bitcoins precision encoding
     * valid number range 0-18,014,398,509,481,983
     * @param {int|BigInt} value
     * @return {string}
     */
    static makeFixedPrecision(value) {
        if (
            (typeof value!="bigint")&&
            ((typeof value=="number")&&(value!==Math.min(value)))
        ) throw new Error("Invalid Input Type");    //throw error if can't be included
        value=BigInt(value);
        if ((value < 0n) || (value > 18014398509481983n)) throw new Error("Invalid Input Type");    //throw error if can't be included

        //see if can be done as 1 byte
        if (value<32n) {
            // noinspection JSCheckFunctionSignatures
            return value.toString(2).padStart(8,'0');
        }

        //compute exponent
        let exponent=0n;
        while (value%10n===0n) {
            exponent++;
            value/=10n;
        }
        if (value>4398046511103n) {                  //max 0 exponent bits
            value*=10n**exponent;
            exponent=0n;
        } else if ((value>33554431n)&&(exponent>7n)) {//max 3 exponent bits
            value*=10n**(exponent-7n);
            exponent=7n;
        }

        //return binary value
        if (value>4398046511103n) {          //7 bytes
            // noinspection JSCheckFunctionSignatures
            return "11"+value.toString(2).padStart(54,'0');
        } else if (value>17179869183n) {     //6 bytes
            // noinspection JSCheckFunctionSignatures
            return "101"+value.toString(2).padStart(42,'0')+exponent.toString(2).padStart(3,'0');
        } else if (value>33554431n) {        //5 bytes
            // noinspection JSCheckFunctionSignatures
            return "100"+value.toString(2).padStart(34,'0')+exponent.toString(2).padStart(3,'0');
        } else if (value>131071n) {          //4 bytes
            // noinspection JSCheckFunctionSignatures
            return "011"+value.toString(2).padStart(25,'0')+exponent.toString(2).padStart(4,'0');
        } else if (value>511n) {             //3 bytes
            // noinspection JSCheckFunctionSignatures
            return "010"+value.toString(2).padStart(17,'0')+exponent.toString(2).padStart(4,'0');
        } else {                            //2 bytes
            // noinspection JSCheckFunctionSignatures
            return "001"+value.toString(2).padStart(9,'0')+exponent.toString(2).padStart(4,'0');
        }
    }

    /**
     * Insert number at end
     * DOES NOT EFFECT POINTER
     * @param {int|BigInt}  value
     */
    appendFixedPrecision(value) {
        this.appendBits(BitIO.makeFixedPrecision(value));
    }

    /**
     * Insert number wherever pointer is
     * @param {int|BigInt}  value
     * @param {boolean} updatePointer
     */
    insertFixedPrecision(value,updatePointer=true) {
        this.insertBits(BitIO.makeFixedPrecision(value),updatePointer);
    }




    /*
    ██████╗ ██╗████████╗ ██████╗ ██████╗ ██╗███╗   ██╗
    ██╔══██╗██║╚══██╔══╝██╔════╝██╔═══██╗██║████╗  ██║
    ██████╔╝██║   ██║   ██║     ██║   ██║██║██╔██╗ ██║
    ██╔══██╗██║   ██║   ██║     ██║   ██║██║██║╚██╗██║
    ██████╔╝██║   ██║   ╚██████╗╚██████╔╝██║██║ ╚████║
    ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
     */
    /**
     * Gets a value that was encoded with bitcoin data encoding
     * @return {Buffer|boolean|int|string}
     */
    getBitcoin() {
        let opCode=this.getInt(8);

        //handle boolean
        if (opCode===0) return 0;

        //handle int
        if (opCode===80) throw new Error("Invalid Op Code");
        if ((opCode>=79)&&(opCode<=96)) return opCode-80;

        //handle Buffer
        if (opCode<=78) {
            let length = opCode;
            if (opCode === 78) length = this.getInt(32);
            if (opCode === 77) length = this.getInt(16);
            if (opCode === 76) length = this.getInt(8);
            return this.getBuffer(length);
        }

        //op codes
        return Object.keys(bitcoinOpCodes).find(key => bitcoinOpCodes[key] === opCode);
    }

    /**
     * Encodes boolean,int -1 to 16, hex string and Buffer to binary
     * @param {boolean,int,string,Buffer}   data
     * @return {string}
     */
    static makeBitcoin(data) {
        //hanlde 0 or false
        // noinspection EqualityComparisonWithCoercionJS
        if (data==0) return '00000000';

        //handle number -1 to 16
        if ((typeof data==="number")&&(Math.floor(data)===data)) {
            if ((data<-1)||(data>16)) throw new Error("Invalid Input Type");
            return (data+80).toString(2).padStart(8,'0');
        }

        //handle hex string input
        if ((typeof data==="string")&&(isHex.test(data))) {
            data=Buffer.from(data,'hex');
        }

        //handle buffer
        let binary='';
        if (Buffer.isBuffer(data)) {
            if (data.length>0xffff) {
                binary='01001110'+data.length.toString(2).padStart(32,'0');
            } else if (data.length>0xff) {
                binary='01001101'+data.length.toString(2).padStart(16,'0');
            } else if (data.length>75) {
                binary='01001100'+data.length.toString(2).padStart(8,'0');
            } else {
                binary=data.length.toString(2).padStart(8,'0');
            }
            for (let i=0;i<data.length;i++) binary+=data[i].toString(2).padStart(8,'0');
            return binary;
        }

        //handle op_code strings
        if (bitcoinOpCodes[data]!==undefined) return bitcoinOpCodes[data].toString(2).padStart(8,'0');

        throw new Error("Invalid Input Type");
    }

    /**
     * Insert value at end
     * DOES NOT EFFECT POINTER
     * @param {boolean|int|string|Buffer}  message
     */
    appendBitcoin(message) {
        this.appendBits(BitIO.makeBitcoin(message));
    }

    /**
     * Insert value wherever pointer is
     * @param {string}  message
     * @param {boolean|int|string|Buffer} updatePointer
     */
    insertBitcoin(message,updatePointer=true) {
        this.insertBits(BitIO.makeBitcoin(message),updatePointer);
    }






    /*
    ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██████╗
    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  ██║  ██║
    ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██║  ██║
    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██████╔╝
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═════╝
     */

    /**
     * Gets and decrypts a Buffer
     * @param {string|Uint8Array}  decryptionPrivateKey
     * @return {Buffer}
     */
    getEncrypted(decryptionPrivateKey) {
        //copy pointer
        let start=this.pointer;

        //get date needed
        const length = parseInt(this.getFixedPrecision());                       //length of encoded data
        const user = new Uint8Array(this.getBuffer(32));   //encrypted public key(generated at random)
        const nonce = new Uint8Array(this.getBuffer(24));  //nonce value
        const box = new Uint8Array(this.getBuffer(length));        //the encrypted data

        //convert key to Uint8Array if not already
        if (typeof decryptionPrivateKey==="string") {
            let key = new Uint8Array(32);
            for (let i = 0; i < 32; i++) key[i] = parseInt(decryptionPrivateKey.substr(2 * i, 2), 16);
            decryptionPrivateKey=key;
        }

        //decrypt encrypted data
        const message = nacl.box.open(box, nonce, user, decryptionPrivateKey);
        if (message===null) {
            this.pointer=start;
            throw new Error("Invalid Key");
        }

        //make output a buffer
        return Buffer.from(message);
    }

    // noinspection JSCheckFunctionSignatures
    /**
     * Encrypts and stores a Buffer.  If encryptionPrivateKey is left blank a random one is created
     *
     * There are 73+x bytes of overhead in this encryption(x is generally a very small number sample below)
     *   data.length:
     *   0-31:     x=0
     *   32-511:   x=1
     *   512-99999:x=2 or 3
     *   ...
     *
     * @param {Buffer}  data
     * @param {string|Uint8Array}  decryptionPublicKey
     * @param {string|Uint8Array}  encryptionPrivateKey
     * @return {string}
     */
    static makeEncrypted(data,decryptionPublicKey,encryptionPrivateKey=undefined) {
        //convert data to Uint8Array
        // noinspection JSCheckFunctionSignatures
        let message = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

        //convert key to Uint8Array
        if (typeof decryptionPublicKey==="string") {
            let key = new Uint8Array(32);
            for (let i = 0; i < 32; i++) key[i] = parseInt(decryptionPublicKey.substr(2 * i, 2), 16);
            decryptionPublicKey=key;
        }

        //generate a key pair for user
        let user;
        if (encryptionPrivateKey===undefined) {

            //create random pair
            user=nacl.box.keyPair();

        } else {

            //create pair from private key
            if (typeof encryptionPrivateKey==="string") {
                let key = new Uint8Array(32);
                for (let i = 0; i < 32; i++) key[i] = parseInt(encryptionPrivateKey.substr(2 * i, 2), 16);
                encryptionPrivateKey=key;
            }
            user=nacl.box.keyPair.fromSecretKey(encryptionPrivateKey);

        }

        //generate random nonce
        const nonce = nacl.randomBytes(24);

        //encrypt message
        const box = nacl.box(
            message,
            nonce,
            decryptionPublicKey,
            user.secretKey
        )

        //compile payload
        let binary=this.makeFixedPrecision(box.length);         //variable length
        binary+=this.makeBuffer(Buffer.from(user.publicKey));   //32 bytes
        binary+=this.makeBuffer(Buffer.from(nonce));            //24 bytes
        binary+=this.makeBuffer(Buffer.from(box));              //variable length
        return binary;
    }

    /**
     * Insert value at end
     * DOES NOT EFFECT POINTER
     * @param {Buffer}  data
     * @param {string|Uint8Array}  decryptionPublicKey
     * @param {string|Uint8Array}  encryptionPrivateKey
     */
    appendEncrypted(data,decryptionPublicKey,encryptionPrivateKey=undefined) {
        this.appendBits(BitIO.makeEncrypted(data,decryptionPublicKey,encryptionPrivateKey));
    }

    /**
     * Insert value wherever pointer is
     * @param {Buffer}  data
     * @param {string|Uint8Array}  decryptionPublicKey
     * @param {string|Uint8Array}  encryptionPrivateKey
     * @param {boolean} updatePointer
     */
    insertEncrypted(data,decryptionPublicKey,encryptionPrivateKey=undefined,updatePointer=true) {
        this.insertBits(BitIO.makeEncrypted(data,decryptionPublicKey,encryptionPrivateKey),updatePointer);
    }





}
module.exports=BitIO;