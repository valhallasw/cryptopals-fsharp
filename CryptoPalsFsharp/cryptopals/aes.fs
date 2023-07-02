namespace cryptopals
open System.IO
open System.Security.Cryptography

module Aes = 
    let decryptEcb paddingmode key enc =
        use aes = Aes.Create()
        aes.Mode <- CipherMode.ECB
        aes.Key <- (key |> Seq.map byte |> Seq.toArray)
        aes.Padding <- paddingmode
        
        let decryptor = aes.CreateDecryptor()
        use msDecrypt = new MemoryStream(enc |> Seq.map byte |> Seq.toArray, false)
        use csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)
        use srDecrypt = new StreamReader(csDecrypt)
        
        srDecrypt.ReadToEnd()

    let verifyLength key block fn =
        let keyLength = Seq.length key
        let blockLength = Seq.length block
        if keyLength = blockLength then fn key block
        else invalidArg (nameof block) $"Block size {blockLength} not equal to key size {keyLength}"

    let encryptBlock key block =
        verifyLength key block (fun key block ->
            use aes = Aes.Create()
            aes.Mode <- CipherMode.ECB
            aes.Key <- (key |> Seq.map byte |> Seq.toArray)
            
            aes.EncryptEcb(block |> Seq.map byte |> Seq.toArray, PaddingMode.None) |> Seq.map int)

    let decryptBlock key block =
        verifyLength key block (fun key block ->
            use aes = Aes.Create()
            aes.Mode <- CipherMode.ECB
            aes.Key <- (key |> Seq.map byte |> Seq.toArray)
            
            aes.DecryptEcb(block |> Seq.map byte |> Seq.toArray, PaddingMode.None) |> Seq.map int)


    let private dup a = (a, a)

    /// <summary>
    /// Encrypt single block, returning an (block, next iv) pair (to be combined with <see cref="Seq.mapFold"/>).
    /// </summary>
    let private encryptCbcBlock (key: seq<int>) (iv: seq<int>) (block: seq<int>) =
        encryptBlock key (Seq.pairxor iv block) |> dup

    // Assumes content is split up in block size chunks
    let private encryptCbcInt (key: seq<int>) (iv: seq<int>) (content: seq<seq<int>>) =
        content |> Seq.mapFold (encryptCbcBlock key) iv |> fst
    
    let encryptCbcPkcs7 (key: seq<int>) (iv: seq<int>) (content: seq<int>) =
        let blocksize = (key |> Seq.length)
        encryptCbcInt key iv (content |> Padding.pad_pkcs7 blocksize |> Seq.splitBlocks blocksize) |> Seq.concat

    let encryptEcbPkcs7 (key: seq<int>) (content: seq<int>) =
        let blocksize = (key |> Seq.length)
        content |> Padding.pad_pkcs7 blocksize |> Seq.splitBlocks blocksize |> Seq.map (encryptBlock key) |> Seq.concat

    let decryptEcbPkcs7 (key: seq<int>) (content: seq<int>) =
        let blocksize = (key |> Seq.length)
        let decrypted = content |> Seq.splitBlocks blocksize |> Seq.map (decryptBlock key) |> Seq.concat |> Seq.toList
        let padding = decrypted[decrypted.Length - 1]
        decrypted[0..decrypted.Length-padding-1]
        
    /// <summary>
    /// Decrypt single block, returning an (block, next iv) pair (to be combined with <see cref="Seq.mapFold"/>).
    /// </summary>
    let private decryptCbcBlock (key: seq<int>) (iv: seq<int>) (block: seq<int>) =
        (Seq.pairxor (decryptBlock key block) iv, block)
        
    // Assumes content is split up in block size chunks
    let private decryptCbcInt (key: seq<int>) (iv: seq<int>) (content: seq<seq<int>>) =
        content |> Seq.mapFold (decryptCbcBlock key) iv |> fst
        
    // need to handle cropping off the padding
    let decryptCbcPkcs7 (key: seq<int>) (iv: seq<int>) (content: seq<int>) =
        let blocksize = (key |> Seq.length)
        let decrypted = decryptCbcInt key iv (content |> Seq.splitBlocks blocksize) |> Seq.concat |> Seq.toList
        let padding = decrypted[decrypted.Length - 1]
        decrypted[0..decrypted.Length-padding-1]

//let encryptCbcPkcs7 key content =
    