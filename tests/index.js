const BitIO = require('../index'),
    events = require('events');
const nacl=require('tweetnacl');

const makeRandom=(length)=>{
    let data=Buffer.alloc(length);
    for (let i=0;i<length;i++) data[i]=Math.floor(Math.random()*256);
    return data;
}


const expect    = require("chai").expect;



describe("Tests",function() {
    it('Bits', async () => {
        let io=BitIO.fromBuffer(new Buffer.from([0x94]));

        expect(io.pointer).to.equal(0);
        expect(io.getBits(6)).to.equal('100101');
        expect(io.pointer).to.equal(6);
        io.insertBits('1001');
        expect(io.pointer).to.equal(10);
        io.appendBits('1101');
        expect(io.pointer).to.equal(10);
        expect(io.getBits(3)).to.equal('001');
        expect(io.pointer).to.equal(13);
        io.pointer=1;
        expect(io.getBits(6)).to.equal('001011');
        expect(io.pointer).to.equal(7);
        expect(io.checkBits('001001')).to.equal(true);
        expect(io.checkBits('001000')).to.equal(false);
        expect(()=>{io.insertBits("f6")});
    });
    it('Buffer', async () => {
        let io=BitIO.fromBuffer(new Buffer.from('940381','hex'));
        io.insertBuffer(new Buffer.from([7]));
        io.appendBuffer(new Buffer.from('7f13','hex'));
        expect(io.toBuffer().toString('hex')).to.equal('079403817f13');
    });
    it('Variable Length', async () => {
        let io=new BitIO();
        io.insertXBitVariableLength('101',3);
        io.appendXBitVariableLength('000000100',3);
        io.insertXBitVariableLength('000001',2);
        io.pointer=0;
        expect(io.getXBitVariableLength(3)).to.equal('101');
        expect(io.getXBitVariableLength(2)).to.equal('000001');
        expect(io.getXBitVariableLength(3)).to.equal('000000100');
        expect(()=>{io.insertXBitVariableLength('1000',2)}).to.throw();
        expect(()=>{io.insertXBitVariableLength('20',2)}).to.throw();
    });
    it('Integers', async () => {
        let io=new BitIO();
        io.insertInt(99,7);
        io.appendInt(10105,15);
        expect(io.getInt(15)).to.equal(10105);
        io.pointer=0;
        expect(io.getInt(7)).to.equal(99);
        expect(()=>{io.insertInt(70000,9)}).to.throw();
    });
    it('Alpha', async () => {
        let io=new BitIO();
        io.insertAlpha('0fiz7+%');
        io.appendAlpha('z1.9');
        expect(io.getAlpha(4)).to.equal('z1.9');
        io.pointer=0;
        expect(io.getAlpha(7)).to.equal('0fiz7+%');
        expect(()=>{io.insertAlpha('A')}).to.throw();
        expect(()=>{io.insertAlpha('&')}).to.throw();
    });
    it('UTF8r', async () => {
        let io=new BitIO();
        io.insertUTF8('0fiz7+%');
        io.appendUTF8('z1.9');
        expect(io.pointer).to.equal(56);
        expect(io.getUTF8(4)).to.equal('z1.9');
        io.pointer=0;
        expect(io.getUTF8(7)).to.equal('0fiz7+%');//TODO
    });
    it('3B40', async () => {
        let io=new BitIO();
        io.insert3B40('exe');
        io.append3B40('pdf');
        expect(io.pointer).to.equal(16);
        expect(io.get3B40(3)).to.equal('pdf');
        io.pointer=0;
        expect(io.get3B40(3)).to.equal('exe');
        io=new BitIO();
        io.insert3B40('tar.gz');
        io.pointer=0;
        expect(io.get3B40(6)).to.equal('tar.gz');
    });
    it('Address', async () => {
        let io=new BitIO();
        io.insertAddress('DUBhARNpy4WYCEWoFQsgeFeYZxQjzQadpv');
        io.appendAddress('Si2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz');
        expect(io.pointer).to.equal(162);
        io.insertAddress('dgb1qcu403j8m7kdsrl74279qhlyg36adkgwdxpf0jl');
        expect(io.getAddress()).to.equal('Si2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz');
        io.pointer=0;
        expect(io.getAddress()).to.equal('DUBhARNpy4WYCEWoFQsgeFeYZxQjzQadpv');
        expect(io.getAddress()).to.equal('dgb1qcu403j8m7kdsrl74279qhlyg36adkgwdxpf0jl');
        expect(()=>{io.insertAddress('dgb1qcu403j8m7kesrl74279qhlyg36adkgwdxpf0jl')}).to.throw();
        expect(()=>{io.insertAddress('3i2n5cEJKAmYxEcJ1Zm9gwufJhco79saMz')}).to.throw();
    });
    it('Fixed Precision', async () => {
        let io=new BitIO();
        io.insertFixedPrecision(5004000);
        io.appendFixedPrecision(19);
        expect(io.pointer).to.equal(24);
        io.insertFixedPrecision(90000000000);
        expect(io.pointer).to.equal(40);
        expect(io.getFixedPrecision()).to.equal(19n);
        io.pointer=0;
        expect(io.getFixedPrecision()).to.equal(5004000n);
        expect(io.getFixedPrecision()).to.equal(90000000000n);
        expect(()=>{io.insertFixedPrecision('s')}).to.throw();
        expect(()=>{io.insertFixedPrecision(null)}).to.throw();
        expect(()=>{io.insertFixedPrecision(19000000000000000)}).to.throw();
    });
    it('Bitcoin', async () => {
        let io=new BitIO();
        io.insertBitcoin(1);
        expect(io.pointer).to.equal(8);
        io.appendBitcoin('OP_CHECKMULTISIGVERIFY');
        expect(io.pointer).to.equal(8);
        io.insertBitcoin(Buffer.from('030123456789012345678901234567890123456789','hex'));
        expect(io.pointer).to.equal(184);
        io.insertBitcoin('02abcdef0123abcdef0123abcdef0123abcdef0123');
        expect(io.pointer).to.equal(360);
        io.insertBitcoin('03ef501cef01689a2b3423018273456db9a4567cd7');
        expect(io.pointer).to.equal(536);
        io.insertBitcoin(3);
        expect(io.pointer).to.equal(544);
        expect(io.getBitcoin()).to.equal('OP_CHECKMULTISIGVERIFY')
        io.pointer=0;
        expect(io.getHex()).to.equal('51150301234567890123456789012345678901234567891502abcdef0123abcdef0123abcdef0123abcdef01231503ef501cef01689a2b3423018273456db9a4567cd753af');
        expect(()=>{io.getBitcoin()}).to.throw();
    });
    it('Hex', async () => {
        let io=new BitIO();
        io.insertHex('5');
        expect(io.pointer).to.equal(4);
        io.appendHex('af0');
        expect(io.pointer).to.equal(4);
        expect(io.getHex(3)).to.equal('af0');
        io.pointer=0;
        expect(io.getHex(4)).to.equal('5af0');
        expect(()=>{io.getHex(1)}).to.throw();
    });
    it('String Optimizer', async () => {
        let io=new BitIO;
        io.insertBestString('exe',5,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        });
        expect(io.pointer).to.equal(23);  //should have chosen 3B40
        expect(()=>{io.appendBestString('https://digiassetx.com',3,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        })}).to.throw();
        expect(io.pointer).to.equal(23);
        io.appendBestString('https://digiassetx.com',5,{
            "01":   "Alpha",
            "10":   "3B40",
            "11":   "UTF8",
            "0001": "Hex"
        });
        expect(io.pointer).to.equal(23);  //should have used Alpha but pointer didn't move
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
        expect(io.getHex()).to.equal('86b96d8054e614cc60cd8c22f2fe2e8981c60df8c10b18456307ec60b78c24c2b585a106c790d90e9b0bb35e7a6b2e420d66a841b2447634a6d55c20d5907b1dd08363c46b2e4d74e841b27035704106b2f9d8f4a41b1e8762a2106b2f9d5c61ab38083617b6c2b5d6591acb90b82941bdc881d5b881b5bdb595b9d1bcb081b9bc81c185ce1e640dcc2c8c25c4098eacacede5840c8cae6e0eb0e97320646520756e20736567756e646f206d870b990379036b2b737b996103730b2309031b7b73a34b73ac3cc81cdd58d9591a595b991bcb82b277de4f55cce13a03f7294de7576d20f19f8f73eb8e7684c9d75a43f73eaae4e0dca7df93b97277de8077c6004d98d532a31ee92dae23bd3ea9d76e89c');
    });
    it('Position Parameters', async () => {
        let io=BitIO.fromBuffer(Buffer.from('DigiByte is an amazing coin'));
        expect(io.pointer).to.equal(0);
        io.movePointer(19);
        expect(io.pointer).to.equal(19);
        expect(()=>io.movePointer(-20)).to.throw();
        io.movePointer(-17);
        expect(io.pointer).to.equal(2);
        expect(io.getHex(1)).to.equal('1');
        expect(io.length).to.equal(216);
        io.padRandom(40);
        expect(io.length).to.equal(246);
        io.pointer=0;
        io.padOne(50);
        expect(io.length).to.equal(250);
    });
    it('Encryption', async () => {
        let io=new BitIO();
        let message=makeRandom(100);
        let pair=nacl.box.keyPair();
        io.appendEncrypted(message,pair.publicKey);
        let decryptedValue=io.getEncrypted(pair.secretKey);
        expect(Buffer.compare(decryptedValue,message)).to.equal(0);
    });
    it('Large Fixed', async () => {
        let io=BitIO.fromBuffer(Buffer.from("802fae67f0","hex"));
        expect(io.getFixedPrecision()).to.equal(99994878n);
        io=new BitIO();
        io.appendFixedPrecision(500000000n);
        expect(io.getFixedPrecision()).to.equal(500000000n);
    });
});

