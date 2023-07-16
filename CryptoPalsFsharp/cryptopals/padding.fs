module Padding

let pad_pkcs7 blocksize input =
    let length = Seq.length input
    let lastblock_size = length % blocksize
    let padding_size = blocksize - lastblock_size
    Seq.append input (Seq.replicate padding_size padding_size)

let strip_padding input =
    let length = input |> Seq.length
    let lastbyte = input |> Seq.last

    if lastbyte > length || lastbyte = 0 then
        None
    else
        let content_len = (length - lastbyte)
        
        let content = input |> Seq.take content_len
        let padding = input |> Seq.skip content_len

        if (padding |> Seq.filter ((=) lastbyte) |> Seq.length |> (=) lastbyte) then
            Some content
        else
            None