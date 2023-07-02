module Padding

let pad_pkcs7 blocksize input =
    let length = Seq.length input
    let lastblock_size = length % blocksize
    let padding_size = blocksize - lastblock_size
    Seq.append input (Seq.replicate padding_size padding_size)
