namespace cryptopals

module hmac =
    let ipad_value = 0x36
    let opad_value = 0x5c
    
    let compute (hash_function: seq<int> -> seq<int>) blocksize key value =
        let ipad = Seq.replicate blocksize ipad_value
        let opad = Seq.replicate blocksize opad_value
        
        let ikey = if (key |> Seq.length > blocksize) then hash_function key else key
        let compute_key = Seq.append ikey (Seq.replicate (blocksize - Seq.length ikey) 0x00)

        let iprefix = Seq.pairxor compute_key ipad
        let oprefix = Seq.pairxor compute_key opad
        
        let hash1 = hash_function (Seq.concat [ iprefix; value ])
        let hash2 = hash_function (Seq.concat [ oprefix; hash1 ])
        hash2
        
    let hmac_sha1 key value = compute (Sha1.hash >> Seq.collect Sha1.unmerge32 >> Seq.map int) 64 key value
