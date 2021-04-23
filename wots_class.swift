import UIKit
import CommonCrypto

extension Collection where Indices.Iterator.Element == Index {
   public subscript(safe index: Index) -> Iterator.Element? {
     return (startIndex <= index && index < endIndex) ? self[index] : nil
   }
}

func sha256_b(ascii: String) -> [UInt8]{
    let data = ascii.data(using: .utf8)
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data!.withUnsafeBytes { buffer in
        _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
    }
    return hash
}
func sha256_b(bytes: [UInt8]) -> [UInt8] {
    let data = Data(bytes)
    var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes { buffer in
        _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
    }
    return hash
}

class WotsClass: ObservableObject {
    let PARAMSN: Int
    let WOTSW: Int
    let WOTSLOGW: Int
    let WOTSLEN1: Int
    let WOTSLEN2: Int
    let WOTSLEN: Int
    let WOTSSIGBYTES: Int

    /* 2144 + 32 + 32 = 2208 */
    let TXSIGLEN: Int
    let TXADDRLEN: Int

    let XMSS_HASH_PADDING_F: Int
    let XMSS_HASH_PADDING_PRF: Int
    init() {
        PARAMSN = 32
        WOTSW = 16
        WOTSLOGW = 4
        WOTSLEN1 = (8 * PARAMSN / WOTSLOGW)
        WOTSLEN2 = 3
        WOTSLEN  = WOTSLEN1 + WOTSLEN2
        WOTSSIGBYTES = WOTSLEN * PARAMSN

        /* 2144 + 32 + 32 = 2208 */
        TXSIGLEN  = 2144
        TXADDRLEN = 2208

        XMSS_HASH_PADDING_F = 0
        XMSS_HASH_PADDING_PRF = 3
    }

    public func public_key_gen(seed: [UInt8], pub_seed: [UInt8], addr_bytes: [UInt8]) -> [UInt8] {
        let private_key: [UInt8] = expand_seed(seed: seed)
        var public_key: [UInt8] = []
        var addr: [String: [UInt8]] = [:]
        addr = bytes_to_addr(addr_bytes: addr_bytes)
        public_key.reserveCapacity(2144)
        
        for i in 0...WOTSLEN-1 {
            set_chain_addr(chain_address: i, addr: &addr)
            let private_key_portion: [UInt8] = Array(private_key[i*PARAMSN...i*PARAMSN+PARAMSN-1])
            let cache_pk: [UInt8] = gen_chain(input: private_key_portion,
                                              start: 0,
                                              steps: WOTSW-1,
                                              pub_seed: pub_seed,
                                              addr: &addr)
            
            public_key.append(contentsOf: cache_pk)
            //let array_to_push = gen_chain()
        }
        return public_key
    }
    public func wots_sign(msg: [UInt8], seed: [UInt8], pub_seed: [UInt8], addr_bytes: [UInt8]) -> [UInt8] {
        let private_key: [UInt8] = expand_seed(seed: seed)
        var signature: [UInt8] = []
        let lenghts: [UInt8] = chain_lenghts(msg: msg)
        var addr: [String: [UInt8]] = [:]
        addr = bytes_to_addr(addr_bytes: addr_bytes)
        signature.reserveCapacity(2144)
        for i in 0...WOTSLEN-1 {
            set_chain_addr(chain_address: i, addr: &addr)
            let private_key_portion: [UInt8] = Array(private_key[i*PARAMSN...i*PARAMSN+PARAMSN-1])
            let cache_sig: [UInt8] = gen_chain(input: private_key_portion,
                                              start: 0,
                                              steps: Int(lenghts[i]),
                                              pub_seed: pub_seed,
                                              addr: &addr)
            signature.append(contentsOf: cache_sig)
        }
        return signature
    }
    public func wots_publickey_from_sig(sig: [UInt8], msg: [UInt8], pub_seed: [UInt8], addr_bytes: [UInt8]) -> [UInt8] {
        var addr = bytes_to_addr(addr_bytes: addr_bytes)
        let lenghts = chain_lenghts(msg: msg)
        var public_key: [UInt8] = []
        public_key.reserveCapacity(2144)
        for i in 0...WOTSLEN-1 {
            set_chain_addr(chain_address: i, addr: &addr)
            let signature_portion: [UInt8] = Array(sig[i*PARAMSN...i*PARAMSN+PARAMSN-1])
            let cache_sig: [UInt8] = gen_chain(input: signature_portion,
                                              start: Int(lenghts[i]),
                                              steps: (WOTSW - 1 - Int(lenghts[i])),
                                              pub_seed: pub_seed,
                                              addr: &addr)
            public_key.append(contentsOf: cache_sig)
        }
        return public_key
    }
    private func expand_seed(seed: [UInt8]) -> [UInt8] {
        var ctr: [UInt8] = [] //This will be max 32 items
        ctr.reserveCapacity(32)
        var out_seeds: [UInt8] = [] //This will be maximum with WOTSLEN items
        out_seeds.reserveCapacity(2144)
        for i in 0...WOTSLEN-1 {
            ctr = ull_to_bytes(outlen: PARAMSN, input: [UInt8(i)]) //yeah I hope "i" doesnt go more than 255
            out_seeds.append(contentsOf: prf(input: ctr, key: seed))
        }
        return out_seeds;
    }
    private func ull_to_bytes(outlen: Int, input: [UInt8]) -> [UInt8] {
        var out_array: [UInt8] = []
        out_array.reserveCapacity(outlen)
        for i in (0...outlen-1).reversed() {
            let to_push = input[safe: i]
            out_array.append(to_push ?? 0)
        }
        return out_array
    }
    private func prf(input: [UInt8], key: [UInt8]) -> [UInt8]{
        var buf: [UInt8] = []
        buf.reserveCapacity(32*3)
        
        buf = ull_to_bytes(outlen: PARAMSN, input: [UInt8(XMSS_HASH_PADDING_PRF)])
        
        let byte_copied_key = byte_copy(source: key, num_bytes: PARAMSN)
        buf.append(contentsOf: byte_copied_key)
        
        let byte_copied_input = byte_copy(source: input, num_bytes: 32)
        buf.append(contentsOf: byte_copied_input)
        
        return sha256_b(bytes: buf)
    }
    private func t_hash(input: [UInt8], pub_seed: [UInt8], addr: inout [String: [UInt8]]) -> [UInt8]{
        var buf: [UInt8] = []
        buf.reserveCapacity(32*3)
        var bitmask: [UInt8]
        var addr_bytes: [UInt8]
        var XOR_bitmask_input: [UInt8] = []
        
        buf.append(contentsOf: ull_to_bytes(outlen: PARAMSN, input: [UInt8(XMSS_HASH_PADDING_F)]))
        
        set_key_and_mask(key_and_mask: 0, addr: &addr)
        addr_bytes = addr_to_bytes(addr: addr)
        buf.append(contentsOf: prf(input: addr_bytes, key: pub_seed))
        
        set_key_and_mask(key_and_mask: 1, addr: &addr)
        addr_bytes = addr_to_bytes(addr: addr)
        bitmask = prf(input: addr_bytes, key: pub_seed)
        
        for i in 0...PARAMSN-1 {
            XOR_bitmask_input.append(input[i] ^ bitmask[i])
        }
        buf.append(contentsOf: XOR_bitmask_input)
        
        return sha256_b(bytes: buf)
    }

    private func gen_chain(input: [UInt8], start: Int, steps: Int, pub_seed: [UInt8], addr: inout [String: [UInt8]]) -> [UInt8]{
        var out = byte_copy(source: input, num_bytes: PARAMSN)
        var i = start
        while(true) {
            if(!(i < (start+steps) && i < WOTSW)) {
                break
            }
            set_hash_addr(hash: i, addr: &addr)
            out = t_hash(input: out, pub_seed: pub_seed, addr: &addr)
            i = i + 1
        }
        return out
    }
    private func byte_copy(source: [UInt8], num_bytes: Int) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(num_bytes)
        
        for i in 0...num_bytes-1 {
            output.append(source[safe: i] ?? 0)
        }
        return output
    }
    private func base_w(outlen: Int, input: [UInt8]) -> [UInt8] {
        var in_ = 0
        var total: UInt8 = UInt8()
        var bits: UInt8 = 0
        var output: [UInt8] = []
        output.reserveCapacity(outlen)
        
        for _ in 0...outlen-1 {
            if(bits == 0) {
                total = input[in_]
                in_  += 1
                bits += 8
            }
            bits -= UInt8(WOTSLOGW)
            output.append((total >> bits) & UInt8( WOTSW - 1))
        }
        
        return output
    }
    private func wots_checksum(msg_base_w: [UInt8]) -> [UInt8] {
        var csum: Int16 = 0
        var csum_bytes: [UInt8] = []
        for i in 0...WOTSLEN1-1 {
            csum = csum + Int16( WOTSW - 1 ) - Int16((msg_base_w[i]))
        }
        /* convert checksum to base_w */
        csum = csum << Int16(8 - ((WOTSLEN2 * WOTSLOGW) % 8))
        csum_bytes = byte_copy(source: from_int_to_byte_array(from: csum ), num_bytes: Int(((WOTSLEN2 * WOTSLOGW + 7) / 8) ))
        let csum_base_w = base_w(outlen: WOTSLEN2, input: csum_bytes)
        return csum_base_w
    }
    private func chain_lenghts(msg: [UInt8]) -> [UInt8] {
        var lenghts: [UInt8] = []
        lenghts.reserveCapacity(67)
        lenghts.append(contentsOf: base_w(outlen: WOTSLEN1, input: msg))
        lenghts.append(contentsOf: wots_checksum(msg_base_w: lenghts))
        return lenghts
    }
    /*
     * Please here chain_address, has and key_and_mask shouldn't be more than 255. If you need it for any reason
     * code it yourself lmao. With standard settings no problem is generated and the code is
     * faster
     */
    private func set_chain_addr(chain_address: Int, addr: inout [String: [UInt8]]){
        addr["5"] = [0,0,0,UInt8(chain_address)]
    }
    private func set_hash_addr(hash: Int, addr: inout [String: [UInt8]]){
        addr["6"] = [0,0,0,UInt8(hash)]
    }
    private func set_key_and_mask(key_and_mask: Int, addr: inout [String: [UInt8]]) {
        addr["7"] = [0,0,0,UInt8(key_and_mask)]
    }
    private func from_int_to_byte_array<T>(from value: T) -> [UInt8] where T: FixedWidthInteger {
        withUnsafeBytes(of: value.bigEndian, Array.init)
    }

    private func addr_to_bytes(addr: [String: [UInt8]]) -> [UInt8] {
        var out_bytes: [UInt8] = []
        out_bytes.reserveCapacity(32)
        
        for i in 0...8-1 {
            out_bytes.append(contentsOf: addr["\(i)"] ?? [0,0,0,0])
        }
        return out_bytes
    }
    private func bytes_to_addr(addr_bytes: [UInt8]) -> [String: [UInt8]] {
        var out_addr: [String: [UInt8]] = ["0": [0,0,0,0], "1": [0,0,0,0], "2": [0,0,0,0], "3": [0,0,0,0],
            "4": [0,0,0,0], "5": [0,0,0,0], "6": [0,0,0,0], "7": [0,0,0,0]
        ]
        for i in 0...7 {
            out_addr["\(i)"] = ull_to_bytes(outlen: 4, input: Array(addr_bytes[i*4...i*4+3]))
        }
        return out_addr
    }
}
