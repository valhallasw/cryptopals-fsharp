namespace cryptopals

open System.Security.Cryptography

//open cryptopals

module Sha1 =
    let merge32 = Seq.fold (fun s (v: uint8) -> ((s <<< 8) ||| (uint32 v))) (uint32 0x00)
    let unmerge32 (x: uint32) = [uint8 (x >>> 24); uint8 (x >>> 16); uint8 (x >>> 8); uint8 x]
    let unmerge64 (x: uint64) = [uint8 (x >>> 56); uint8 (x >>> 48); uint8 (x >>> 40); uint8 (x >>> 32); uint8 (x >>> 24); uint8 (x >>> 16); uint8 (x >>> 8); uint8 x]
    let hashToHex (input: seq<uint32>) =
        input |> Seq.collect unmerge32 |> Seq.map int |> Hex.byteToHex
    let pad (content: seq<uint8>): seq<uint32> =
        let length = (Seq.length content) * 8
        let padding_bits = 512 - (length + 1 + 64) % 512
         
        
        (Seq.concat [
            content;
            Seq.singleton (uint8 0x80);
            Seq.replicate (padding_bits / 8) (uint8 0x00)
            unmerge64 (uint64 length)
        ] |> Seq.splitBlocks 4 |> Seq.map merge32)

    let rot n (x: uint32) = (x <<< n) ||| (x >>> (32 - n))
    
    let process_chunk (h0, h1, h2, h3, h4) (chunk: uint32 array) =
        let unfolder (state: uint32 array) =
            // state is the _inversed_ array, i.e. new values get _prepended_
            let value = rot 1 (state[2] ^^^ state[7] ^^^ state[13] ^^^ state[15])

            Some (value, Array.concat [ Array.singleton value; Array.take 15 state ])
            
        let schedule (chunk: uint32 array) =
            Seq.concat [
                    chunk |> Array.toSeq
                    Seq.unfold unfolder (chunk |> Array.rev) |> Seq.take (80-16)
            ]
        
        // state -> t -> state
        let folder ((a,b,c,d,e): (uint32 * uint32 * uint32 * uint32 * uint32)) (i, w) =
            let f = match i with
                    | i' when i' < 20 -> (b &&& c) ||| ((~~~ b) &&& d)
                    | i' when i' < 40 -> (b ^^^ c ^^^ d)
                    | i' when i' < 60 -> (b &&& c) ||| (b &&& d) |||  (c &&& d)
                    | _ -> (b ^^^ c ^^^ d)
            
            let k = match i with
                    | i' when i' < 20 -> (uint32) 0x5A827999
                    | i' when i' < 40 -> (uint32) 0x6ED9EBA1
                    | i' when i' < 60 -> (uint32) 0x8F1BBCDC
                    | _ -> (uint32) 0xCA62C1D6
                
            let temp = (rot 5 a) + f + e + k + w
            (temp, a, (rot 30 b), c, d)
        
        let scheduled = chunk |> schedule
        let (a,b,c,d,e) = (scheduled |> Seq.indexed |> Seq.fold folder (h0, h1, h2, h3, h4))

        //printfn "Original state: %08x %08x %08x %08x %08x" h0 h1 h2 h3 h4
        //printfn "Chunk: %s" (chunk |> Seq.collect unmerge32 |> Seq.map int |> Hex.byteToHex)
        //printfn "Computed: %08x %08x %08x %08x %08x" a b c d e
        //printfn "New state: %08x %08x %08x %08x %08x" (h0 + a) (h1 + b) (h2 + c) (h3 + d) (h4 + e)
        (h0 + a, h1 + b, h2 + c, h3 + d, h4 + e)

    let hash_internal initial input: uint32 list = 
        let padded = pad (input |> Seq.map uint8)
        let chunks = padded |> Seq.splitBlocks (512 / 32) |> Seq.map Seq.toArray
        let (h0, h1, h2, h3, h4) = chunks |> Seq.fold process_chunk initial
        
        [h0; h1; h2; h3; h4]

    let hash: seq<int> -> uint32 list =
        hash_internal (uint32 0x67452301, uint32 0xEFCDAB89, uint32 0x98BADCFE, uint32 0x10325476, uint32 0xC3D2E1F0)

module Sha256 =
    let hash value = 
        (value |> Seq.map byte |> Seq.toArray) |> SHA256.HashData |> Seq.map int
       


        
        