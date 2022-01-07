import { KeyPair, Bn, Hash, Point, PubKey, Bsm, Address, PrivKey, Aescbc } from 'openspv'
import { jst } from '@/global/index'
const G = Point.getG()
const N = Point.getN()

class Server {
    constructor(paymail, pubKeyString, mongo = {}) {
        this.userPubKey = PubKey.fromString(pubKeyString)
        this.db = mongo
        this.userPaymail = paymail
        this.localReceiveUrl =
            process.env.VERCEL_URL === 'localhost:3000'
                ? 'http://localhost:3000/api/paymail/receiveMessage/' + paymail
                : process.env.PAYMAIL_API_ROOT + '/api/paymail/receiveMessage/' + paymail
    }

    async register(conversation) {
        try {
            const time = Date.now()
            await this.db.collection('connections').insertOne({ ...conversation, createdAt: time, updatedAt: time })
        } catch (error) {
            console.log({ error })
        }
    }

    deriveMessagePoint(MessageBuf) {
        const cId = Hash.sha256(MessageBuf).toString('hex')
        const mBn = Bn.fromBuffer(Buffer.from(cId, 'hex'))
        const M = G.mul(mBn)
        return { MessageBuf, cId, M }
    }

    acceptConnection(Message, conversationId, originator) {
        const { paymail, connectionKey, sig } = originator
        const MessageBuf = Buffer.from(jst(Message), 'utf8')
        const { cId, M } = this.deriveMessagePoint(MessageBuf)
        if (cId !== conversationId) return { error: 'cId does not match conversationId' }
        const pubKey = this.userPubKey
        pubKey.point = pubKey.point.add(M)
        const valid = Bsm.verify(MessageBuf, sig, Address.fromPubKey(PubKey.fromString(connectionKey)))
        if (!valid) return { accepted: false }
        return { connectionKey: pubKey.toString(), accepted: true }
    }
}

class Client {
    constructor(userPaymail, privKey) {
        this.userKeyPair = KeyPair.fromPrivKey(privKey)
        this.userPaymail = userPaymail
        this.register = {}
    }

    newMessage(members = [], subject) {
        const Message = { members, subject, createdAt: Date.now() }
        const MessageBuf = Buffer.from(jst(Message), 'utf8')
        const conversationId = Hash.sha256(MessageBuf).toString('hex')
        const mBn = new Bn().fromBuffer(Buffer.from(conversationId, 'hex'))
        const M = G.mul(mBn)
        return { Message, conversationId, mBn, M }
    }

    requestConnection(members = [], subject = 'Chat') {
        const { Message, conversationId, mBn, M } = this.newMessage(members, subject)
        const p = mBn.add(this.userKeyPair.privKey.bn).mod(N)
        const sig = Bsm.sign(Buffer.from(jst(Message), 'utf8'), KeyPair.fromPrivKey(PrivKey.fromBn(p)))
        const userPubKey = this.userKeyPair.pubKey
        userPubKey.point = userPubKey.point.add(M)
        const connectionKey = userPubKey.toString()
        /* console.log({requestConnection:{
            Message,
            conversationId,
            connectionKey,
            sig,
        } })*/
        return {
            Message,
            conversationId,
            connectionKey,
            sig,
        }
    }

    deriveMessagePoint(conversationId) {
        const mBn = Bn.fromBuffer(Buffer.from(conversationId, 'hex'))
        const M = G.mul(mBn)
        return { M }
    }

    calculatePublicEdges(conversation) {
        const { conversationId, members } = conversation
        const { M } = this.deriveMessagePoint(conversationId)
        const otherMembers = members?.filter(m => m.paymail !== this.userPaymail)
        otherMembers?.map(member => {
            // this member needs one thing to be able to make a conversationSecret,
            // and that is the publicEdges and corresponding messageKey of the other two members' connection
            // we are going to give this member our corresponding non-them publicEdges.

            // we calculate the secret with this member, and corresponding publicEdge,
            // and give that edge to all OTHER member, but not them
            // the connectionKey for each member should be their pubKey point added to the messagePoint
            const s = this.calcS(conversationId, member?.connectionKey)
            const edge = PubKey.fromPrivKey(PrivKey.fromBn(s)).toString()

            // we then take this secret and share it with others
            otherMembers
                .filter(m => m.paymail !== member.paymail) // but not the current member (as they have the s already)
                .map(shareWithMember => {
                    const edges = new Set()
                    // adding edges from other users
                    if (shareWithMember?.publicEdges) shareWithMember.publicEdges?.map(e => edges.add(e))
                    // no need to add more than is absolutely necessary, not the same key twice
                    if (edges.size >= conversation?.target || edges.has(edge)) return
                    // otherwise add it
                    edges.add(edge)
                    shareWithMember.publicEdges = Array.from(edges)
                    const newMessageKey = shareWithMember?.messageKey
                        ? PubKey.fromString(shareWithMember.messageKey)
                        : new PubKey(M, true)
                    newMessageKey.point = newMessageKey.point.mul(s)
                    shareWithMember.messageKey = newMessageKey.toString()
                })
        })
        conversation.hasAddedEdges = !!conversation?.hasAddedEdges
            ? conversation.hasAddedEdges.concat([this.userPaymail])
            : [this.userPaymail]
        return conversation
    }

    calcS(conversationId, connectionKey) {
        const S = PubKey.fromString(connectionKey).point.mul(
            Bn.fromBuffer(Buffer.from(conversationId, 'hex')).add(this.userKeyPair.privKey.bn).mod(N)
        )
        const t = Buffer.from(S.x.toArray())
        const s = Hash.sha256(t) // force 32 bytes
        return new Bn().fromBuffer(s).mod(N)
    }

    calcConversationSecret(conversation) {
        if (conversation === undefined) return
        const { conversationId, members } = conversation
        const thisMembers = members.find(m => m.paymail === this.userPaymail)
        const connectionSecrets = members
            .filter(m => m.paymail !== this.userPaymail)
            .map(m => {
                const s = this.calcS(conversationId, m.connectionKey)
                const publicEdge = PubKey.fromPrivKey(PrivKey.fromBn(s)).toString()
                return { publicEdge, s }
            })
        const { M } = this.deriveMessagePoint(conversationId)
        let messagePoint = thisMembers?.messageKey
            ? PubKey.fromString(thisMembers.messageKey).point
            : new PubKey(M, true).point
        connectionSecrets
            .filter(c => {
                return !thisMembers?.publicEdges?.includes(c.publicEdge)
            })
            .map(c => (messagePoint = messagePoint.mul(c.s)))
        const t = Buffer.from(messagePoint.x.toArray())
        const s = Hash.sha256(t) // force 32 bytes
        //console.log({ convoS: s.toString('hex') })
        this.register[conversationId] = { s }
    }

    encryptPayload(payload, conversationId) {
        const payloadBuf = Buffer.from(payload, 'utf8')
        const encrypted = Aescbc.encrypt(payloadBuf, this.register[conversationId].s)
        return encrypted.toString('base64')
    }

    decryptPayload(encrypted, conversationId) {
        try {
            const encryptedMessageBuf = Buffer.from(encrypted, 'base64')
            const decrypted = Aescbc.decrypt(encryptedMessageBuf, this.register[conversationId].s)
            return decrypted.toString()
        } catch (error) {
            // console.log(error)
            return jst({
                v: '0.0.1',
                createdAt: Date.now(),
                from: {
                    paymail: 'unknown@paymail.com',
                },
                content: {
                    html: '<div><p>Unable to decrypt</p></div>',
                },
            })
        }
    }
}

export { Server, Client }
