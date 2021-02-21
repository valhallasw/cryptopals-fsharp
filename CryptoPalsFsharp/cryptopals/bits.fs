module Bits

let rec private binarizer max n =
    if max = 0 then []
    elif n >= max then ([1] @ (binarizer (max/2) (n-max)))
    else ([0] @ (binarizer (max/2) (n)))
let binarize8 = binarizer 128

let unbinarize = List.fold (fun c v -> 2*c + v) 0 //or... ((*) 2 >> (+)) 0

let bytesToBits = List.collect binarize8