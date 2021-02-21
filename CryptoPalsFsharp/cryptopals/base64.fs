module Base64
open cryptopals

let private base64table = Array.ofSeq "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let private base64Lookup i = Array.item i base64table

let private padUntilLengthMultiple length value list =
    let i = length - (List.length list) % length
    if (i = length) then list
    else list @ (List.replicate i value)

let private padChunkLeft = padUntilLengthMultiple 6 0 
let private padBase64 = padUntilLengthMultiple 4 '='

let byteToBase64 (x: bytearray) =
    Bits.bytesToBits x |>
    List.chunkBySize 6 |>
    List.map padChunkLeft |>
    List.map Bits.unbinarize |>
    List.map base64Lookup |>  // (Array.item >> (|>) base64table) |>   // equivalent to fun i -> Array.item i base64table, i.e. look up in List
    padBase64 |>
    List.map string |>
    String.concat ""
