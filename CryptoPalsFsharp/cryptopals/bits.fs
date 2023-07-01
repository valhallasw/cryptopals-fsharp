module Bits

let rec private binarizer max n =
    if max = 0 then []
    elif n >= max then ([ 1 ] @ (binarizer (max / 2) (n - max)))
    else ([ 0 ] @ (binarizer (max / 2) (n)))

let binarize8 = binarizer 128
let binarize6 = binarizer 32

let unbinarize: seq<int> -> int = Seq.fold (fun c v -> 2 * c + v) 0 //or... ((*) 2 >> (+)) 0

let bytesToBits: seq<int> -> seq<int> = Seq.collect binarize8
