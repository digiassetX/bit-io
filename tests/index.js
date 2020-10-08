require('nodeunit');
const BitIO = require('../index'),
    events = require('events');
const nacl=require('tweetnacl');

const makeRandom=(length)=>{
    let data=Buffer.alloc(length);
    for (let i=0;i<length;i++) data[i]=Math.floor(Math.random()*256);
    return data;
}

module.exports = {
    'test Bits': function(test) {
        let io=BitIO.fromBuffer(new Buffer.from([0x94]));
        test.equal(io.pointer,0);
        test.equal(io.getBits(6), '100101');
        test.equal(io.pointer,6);
        io.insertBits('1001');
        test.equal(io.pointer,10);
        io.appendBits('1101');
        test.equal(io.pointer,10);
        test.equal(io.getBits(3), '001');
        test.equal(io.pointer,13);
        io.pointer=1;
        test.equal(io.getBits(6), '001011');
        test.equal(io.pointer,7);
        test.equal(io.checkBits('001001'),true);
        test.equal(io.checkBits('001000'),false);
        test.throws(()=>{io.insertBits("f6")});
        test.done();
    },
    'test Buffer': function(test) {
        let io=BitIO.fromBuffer(new Buffer.from('940381','hex'));
        io.insertBuffer(new Buffer.from([7]));
        io.appendBuffer(new Buffer.from('7f13','hex'));
        test.equal(io.toBuffer().toString('hex'),'079403817f13');
        test.done();
    },
    'test Variable Length': function(test) {
        let io=new BitIO();
        io.insertXBitVariableLength('101',3);
        io.appendXBitVariableLength('000000100',3);
        io.insertXBitVariableLength('000001',2);
        io.pointer=0;
        test.equal(io.getXBitVariableLength(3),'101');
        test.equal(io.getXBitVariableLength(2),'000001');
        test.equal(io.getXBitVariableLength(3),'000000100');
        test.throws(()=>{io.insertXBitVariableLength('1000',2)});
        test.throws(()=>{io.insertXBitVariableLength('20',2)});
        test.done();
    },
    'test Integers': function(test) {
        let io=new BitIO();
        io.insertInt(99,7);
        io.appendInt(10105,15);
        test.equal(io.getInt(15),10105);
        io.pointer=0;
        test.equal(io.getInt(7),99);
        test.throws(()=>{io.insertInt(70000,9)});
        test.done();
    },
    'test Alpha': function(test) {
        let io=new BitIO();
        io.insertAlpha('0fiz7+%');
        io.appendAlpha('z1.9');
        test.equal(io.getAlpha(4),'z1.9');
        io.pointer=0;
        test.equal(io.getAlpha(7),'0fiz7+%');
        test.throws(()=>{io.insertAlpha('A')});
        test.throws(()=>{io.insertAlpha('&')});
        test.done();
    },
    'test utf8': function(test) {
        let io=new BitIO();
        io.insertUTF8('0fiz7+%');
        io.appendUTF8('z1.9');
        test.equal(io.pointer,56);
        test.equal(io.getUTF8(4),'z1.9');
        io.pointer=0;
        test.equal(io.getUTF8(7),'0fiz7+%');//TODO
        test.done();
    },
    'test 3B40': function(test) {
        let io=new BitIO();
        io.insert3B40('exe');
        io.append3B40('pdf');
        test.equal(io.pointer,16);
        test.equal(io.get3B40(3),'pdf');
        io.pointer=0;
        test.equal(io.get3B40(3),'exe');
        test.done();
    },
    'test address': function(test) {
        let io=new BitIO();
        io.insertAddress('DUBhARNpy4WYCEWoFQsgeFeYZxQjzQadpv');
        io.appendAddress('Si2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz');
        test.equal(io.pointer,162);
        io.insertAddress('dgb1qcu403j8m7kdsrl74279qhlyg36adkgwdxpf0jl');
        test.equal(io.getAddress(),'Si2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz');
        io.pointer=0;
        test.equal(io.getAddress(),'DUBhARNpy4WYCEWoFQsgeFeYZxQjzQadpv');
        test.equal(io.getAddress(),'dgb1qcu403j8m7kdsrl74279qhlyg36adkgwdxpf0jl');
        test.throws(()=>{io.insertAddress('dgb1qcu403j8m7kesrl74279qhlyg36adkgwdxpf0jl')});
        test.throws(()=>{io.insertAddress('3i2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz')});
        test.done();
    },
    'test fixed precision': function(test) {
        let io=new BitIO();
        io.insertFixedPrecision(5004000);
        io.appendFixedPrecision(19);
        test.equal(io.pointer,24);
        io.insertFixedPrecision(90000000000);
        test.equal(io.pointer,40);
        test.equal(io.getFixedPrecision(),19);
        io.pointer=0;
        test.equal(io.getFixedPrecision(),5004000);
        test.equal(io.getFixedPrecision(),90000000000);
        test.throws(()=>{io.insertFixedPrecision('s')});
        test.throws(()=>{io.insertFixedPrecision(null)});
        test.throws(()=>{io.insertFixedPrecision(19000000000000000)});
        test.done();
    },
    'test bitcoin': function(test) {
        let io=new BitIO();
        io.insertBitcoin(1);
        test.equal(io.pointer,8);
        io.appendBitcoin('OP_CHECKMULTISIGVERIFY');
        test.equal(io.pointer,8);
        io.insertBitcoin(Buffer.from('030123456789012345678901234567890123456789','hex'));
        test.equal(io.pointer,184);
        io.insertBitcoin('02abcdef0123abcdef0123abcdef0123abcdef0123');
        test.equal(io.pointer,360);
        io.insertBitcoin('03ef501cef01689a2b3423018273456db9a4567cd7');
        test.equal(io.pointer,536);
        io.insertBitcoin(3);
        test.equal(io.pointer,544);
        test.equal(io.getBitcoin(),'OP_CHECKMULTISIGVERIFY')
        io.pointer=0;
        test.equal(io.getHex(),'51150301234567890123456789012345678901234567891502abcdef0123abcdef0123abcdef0123abcdef01231503ef501cef01689a2b3423018273456db9a4567cd753af');
        test.throws(()=>{io.getBitcoin()});
        test.done();
    },
    'Test hex': function(test) {
        let io=new BitIO();
        io.insertHex('5');
        test.equal(io.pointer,4);
        io.appendHex('af0');
        test.equal(io.pointer,4);
        test.equal(io.getHex(3),'af0');
        io.pointer=0;
        test.equal(io.getHex(4),'5af0');
        test.throws(()=>{io.getHex(1)});
        test.done();
    },
    'Test string optimizer': function(test) {
        let io=new BitIO;
        io.insertBestString('exe',5,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        });
        test.equal(io.pointer,23);  //should have chosen 3B40
        test.throws(()=>{io.appendBestString('https://digiassetx.com',3,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        })});
        test.equal(io.pointer,23);
        io.appendBestString('https://digiassetx.com',5,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        });
        test.equal(io.pointer,23);  //should have used Alpha but pointer didn't move
        io.insertBestString(
            '慌てる必要はありません'+"\n"+
            '내 자존심보다 더 중요한 것이 있다면 지금 당장 잡아 당기고 싶습니다.'+"\n"+
            'Por un momento, no pasó nada. Luego, después de un segundo más o menos, nada continuó sucediendo.'+"\n"+
            '任何有能力當選總統的人都絕不可以任職。',16,{
            "01":   "Alpha",
            "11":   "UTF8",
            "0001": "Hex"
        });
        io.pointer=0;
        io.padZero(4);  //make sure output can be converted to hex

        io.pointer=0;
        test.equal(io.getHex(),'86b96d8054e614cc60cd8c22f2fe2e8981c60df8c10b18456307ec60b78c24c2b585a106c790d90e9b0bb35e7a6b2e420d66a841b2447634a6d55c20d5907b1dd08363c46b2e4d74e841b27035704106b2f9d8f4a41b1e8762a2106b2f9d5c61ab38083617b6c2b5d6591acb90b82941bdc881d5b881b5bdb595b9d1bcb081b9bc81c185ce1e640dcc2c8c25c4098eacacede5840c8cae6e0eb0e97320646520756e20736567756e646f206d870b990379036b2b737b996103730b2309031b7b73a34b73ac3cc81cdd58d9591a595b991bcb82b277de4f55cce13a03f7294de7576d20f19f8f73eb8e7684c9d75a43f73eaae4e0dca7df93b97277de8077c6004d98d532a31ee92dae23bd3ea9d76e89c');
        test.done();
    },
    'Test position parameters': function(test) {
        let io=BitIO.fromBuffer(Buffer.from('DigiByte is an amazing coin'));
        test.equal(io.pointer,0);
        io.movePointer(19);
        test.equal(io.pointer,19);
        test.throws(()=>io.movePointer(-20));
        io.movePointer(-17);
        test.equal(io.pointer,2);
        test.equal(io.getHex(1),'1');
        test.equal(io.length,216);
        io.padRandom(40);
        test.equal(io.length,246);
        io.pointer=0;
        test.equal(io.padOne(50));
        test.equal(io.length,250);
        test.done();
    },
    'Test encryption:': function(test) {
        let io=new BitIO();
        let message=makeRandom(100);
        let pair=nacl.box.keyPair();
        io.appendEncrypted(message,pair.publicKey);
        test.equal(Buffer.compare(io.getEncrypted(pair.secretKey),message),0);
        test.done();
    }

};

