# Bit-IO



## Installation
``` bash
npm install bit-io
```

## Usage
#### Create BitIO object:
Create a blank BitIO object using:
``` javascript
let io=new BitIO();
```

or create an object with data populated using*:
``` javascript
let io=BitIO.fromBuffer(someBuffer);
```
*limited to multiple of 8bits this way

#### Data commands
There are 3 functions for each encoding type.  Put the command before the encoding type for each function name.

Commands:
```
    get:               Gets the data at the current pointer and moves pointer to the end of the value.
    insert:            Inserts data at the current pointer and moves pointer to end of new data.
    append:            Appends data to the end.  Does NOT move pointer.
```

Encoding formats requiring length:
```
    Bits:               string of "1" and "0"
    Int:                integer number from 0 to 2^length-1
    Alpha:              encodes a string using QR code alphanumeric encoding(uses lower case though)
    UTF8:               encodes a string using a modified version of UTF8.  Same except redundant bits have been
                        removed
    Hex:                encodes a string made up of hexadecimal characters
    3B40:  
```

Encoding formats not requiring length:
```
    XBitVariableLength: string of "1" and "0" but with no fixed length.  Bits are taken X bits at a time until at
                        least 1 bit is "1"
    Address:            encodes a string containing a DigiByte address
    FixedPrecision:     encodes a number using bitcoins fixed precision encoding
```

#### Move Pointer
Can move the pointer in 2 ways
```javascript
    io.movePointer(-2);  //moves the pointer back 2 bits
    io.pointer=0;        //moves the pointer to the first bit
```

#### Pad Data
Some times we need to pad the data to allow exporting in a specific format.  There are 3 pad functions for this.  All 3 calculate the padding multiple from the current pointer not from the beginning.
```javascript
    io.padZero(8);       //pads end with 0s to a multiple of 8 bits
    io.padOne(4);        //pads end with 1s to a multiple of 4 bits
    io.padRandom(16);    //pads end with random data to a multiple of 16 bits
```

