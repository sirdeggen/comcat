const bsv = require('bsv')
const { KeyPair, Bn, Hash, Point, PubKey, Bsm, Address, PrivKey, Aescbc } = bsv
const G = Point.getG()
const N = Point.getN()

class ComCat {
    constructor() {
        this.userKeyPair = KeyPair.fromRandom()
        this.register = {}
    }

    newMessage(server = 'counterparty', Message = undefined) {
        if (!Message) Message = Buffer.from(String(Date.now()) + String(server))
        const m = new Bn().fromBuffer(Hash.sha256(Message))
        const mG = G.mul(m)
        return { Message, m, mG }
    }

    requestConnection(server = 'counterparty') {
        const { Message, m, mG } = this.newMessage(server)
        this.register[server] = { Message, m, mG }
        const MessageString = Message.toString()
        return {
            MessageString,
            pubKey: this.userKeyPair.pubKey.toString(),
        }
    }

    acceptConnection(MessageString, pubKeyString, server = 'counterparty') {
        const Message = Buffer.from(MessageString)
        const { m, mG } = this.newMessage(server, Message)
        const pubKey = PubKey.fromString(pubKeyString)
        pubKey.point = pubKey.point.add(mG)
        this.register[server] = { Message, m, mG, pubKey }
        return { pubKeyString: this.userKeyPair.pubKey.toString() }
    }

    storePubKey(pubKeyString, server = 'counterparty') {
        const pubKey = PubKey.fromString(pubKeyString)
        pubKey.point = pubKey.point.add(this.register[server].mG)
        this.register[server].pubKey = pubKey
        console.log('stored in ', server)
    }

    signMessage(server = 'counterparty') {
        const { Message, m } = this.register[server]
        const p = m.add(this.userKeyPair.privKey.bn).mod(N)
        const sig = Bsm.sign(Message, KeyPair.fromPrivKey(PrivKey.fromBn(p)))
        return { sig: sig.toString() }
    }

    verifySignature(sig, server = 'counterparty') {
        const { Message, pubKey, m } = this.register[server]
        const valid = Bsm.verify(Message, sig, Address.fromPubKey(pubKey))
        console.log({ valid })
        if (valid) {
            this.register[server].sig = sig
            this.register[server].s = pubKey.point.mul(m.add(this.userKeyPair.privKey.bn).mod(N)).x.toBuffer()
            console.log({ s: this.register[server].s.toString('hex') })
        }
    }

    calcS(server = 'counterparty') {
        const { pubKey, m } = this.register[server]
        this.register[server].s = pubKey.point.mul(m.add(this.userKeyPair.privKey.bn).mod(N)).x.toBuffer()
        console.log({ s: this.register[server].s.toString('hex') })
    }

    encryptMessage(message, server = 'counterparty') {
        const messageBuf = Buffer.from(message)
        const encrypted = Aescbc.encrypt(messageBuf, this.register[server].s)
        return encrypted.toString('hex')
    }

    decryptMessage(encryptedMessage, server = 'counterparty') {
        const encryptedMessageBuf = Buffer.from(encryptedMessage, 'hex')
        const decrypted = Aescbc.decrypt(encryptedMessageBuf, this.register[server].s)
        return decrypted.toString()
    }
}

const A = new ComCat()
const B = new ComCat()

const { MessageString, pubKey } = A.requestConnection()
const { pubKeyString } = B.acceptConnection(MessageString, pubKey)
A.storePubKey(pubKeyString)
const { sig } = A.signMessage()
B.verifySignature(sig)
A.calcS()