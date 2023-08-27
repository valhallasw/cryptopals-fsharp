module set4

open System
open System.Net
open System.Threading
open Microsoft.FSharp.Collections
open Microsoft.FSharp.Control
open NUnit.Framework
open FsUnit
open Suave.Utils
open cryptopals
open Suave
open FsHttp
open Suave.Filters
open Suave.Operators
open Suave.Successful

[<Test>]
let challenge25 () =
    let _key = Random.randomBytes 16
    let _nonce = Random.randomBytes 8
    let _content = File.readChallengeData "25.txt" |> String.concat "" |>
                   Base64.base64ToByte |>
                   Aes.decryptEcbPkcs7 ("YELLOW SUBMARINE" |> Ascii.charToByte)
    
    let ciphertext = _content |> Aes.encryptCtr _key _nonce
    
    let _changeContent key nonce enc index newtext =
        let keystream = Aes.genAesCtrStream key nonce
        Seq.concat [
            enc |> Seq.take index
            Seq.pairxor newtext (keystream |> Seq.skip index)
            enc |> Seq.skip index |> Seq.skip (Seq.length newtext)
        ]
    
    let changeContent = _changeContent _key _nonce
    
    // test whether this works...
    let c = "Hello, I like cookies" |> Ascii.charToByte |> Aes.encryptCtr _key _nonce
    let c1 = changeContent c 14 ("poc" |> Ascii.charToByte)
    
    c1 |> Aes.decryptCtr _key _nonce |> Ascii.byteToChars |> should equal "Hello, I like pockies"
    
    // great. Now we can recover the keystream from the ciphertext by replacing the content with
    // nul bytes
    let keystream = changeContent ciphertext 0 (Seq.replicate (Seq.length ciphertext) 0)
    
    // and thus we can decrypt the original ciphertext
    let content = Seq.pairxor ciphertext keystream
    content |> Seq.take 25 |> Ascii.byteToChars |> should equal "I'm back and I'm ringin' "

let challenge26enc_template key nonce contents =
    let dec = ["comment1=cooking%20MCs;userdata="; contents |> String.urlencode; ";comment2=%20like%20a%20pound%20of%20bacon"] |> String.concat ""
    
    Aes.encryptCtr key nonce (dec |> Ascii.charToByte)

let challenge26oracle_template key nonce enc =
    let decrypted = enc |> Aes.decryptCtr key nonce
    decrypted |> Ascii.byteToChars |> Utils.printsn
    decrypted |> (Ascii.byteToChars >> fun f -> f.Contains(";admin=true;"))

[<Test>]
let challenge26 () =
    let _key = Random.randomBytes 16
    let _nonce = Random.randomBytes 8
    
    let enc = challenge26enc_template _key _nonce
    let check = challenge26oracle_template _key _nonce
    
    // method: repeat 100 'A's. Split the resulting ciphertext in 'first 40 bytes', 'X bytes that will become the
    // content we want', 'the rest'. Assume the X bytes are A's XORed with the keystream. XOR the encrypted stream
    // with ('A' ^ target_byte). Rinse and repeat.
    
    let content = ";admin=true;" |> Ascii.charToByte
    let content_length = content |> Seq.length
    let content_xor_A = content |> Seq.pairxor (Seq.replicate content_length (int 'A'))

    let encrypted = enc (Seq.replicate 100 (int 'A') |> Ascii.byteToChars)
    let new_enc = Seq.concat [
            encrypted |> Seq.take 40
            encrypted |> Seq.skip 40 |> Seq.take content_length |> Seq.pairxor content_xor_A
            encrypted |> Seq.skip 40 |> Seq.skip content_length
    ]
    
    check new_enc |> should equal true

let challenge27enc_template key contents =
    let dec = ["comment1=cooking%20MCs;userdata="; contents |> String.urlencode; ";comment2=%20like%20a%20pound%20of%20bacon"] |> String.concat ""
    
    Aes.encryptCbcPkcs7 key key (dec |> Ascii.charToByte)
    
let challenge27dec_template key enc =
    let dec = Aes.decryptCbcPkcs7 key key enc
    
    match dec with
    | None -> "Invalid padding"
    | Some(v) ->
        let plaintext = v |> Seq.map (char >> string) |> String.concat ""
        plaintext |> Utils.printsn
        
        if (Seq.countf (Ascii.isprintable >> not) v) = 0
            then (if plaintext.Contains(";admin=true;") then "ADMIN" else "USER")
            else "Error: invalid content " + plaintext

[<Test>]
let challenge27 () =
    let _key = Random.randomBytes 16
    
    let enc = challenge27enc_template _key
    let dec = challenge27dec_template _key
    
    let encrypted = enc "whatever"
    encrypted |> dec |> should equal "USER"
    
    let blocks = encrypted |> Seq.splitBlocks 16 |> Seq.toArray
    
    
    let attack = Seq.concat [
        blocks[0]
        (Seq.replicate 16 0x00)
        blocks[0]
        blocks |> Seq.concat
    ]
    
    let attack_decrypt = attack |> dec |> Seq.map int |> Seq.skip (Seq.length "Error: invalid content ") |> Seq.splitBlocks 16 |> Seq.toArray
    let key' = Seq.pairxor attack_decrypt[0] attack_decrypt[2]
    
    key' |> should equal _key
    
let keyedsha key content =
    Seq.concat [
        key;
        content;
    ] |> Sha1.hash
    
let generate_mac = keyedsha
let validate_mac key x mac = Seq.allEqual (generate_mac key x) mac

[<Test>]
let challenge28 () =
    let _key = Random.randomBytes 16
    let gen = generate_mac _key
    let validate = validate_mac _key
    
    let message = "My validated message" |> Ascii.charToByte
    let mac = gen message
    
    validate message mac |> should equal true
    
    let notmessage = "Some other message" |> Ascii.charToByte
    
    validate notmessage mac |> should equal false
    
[<Test>]
let challenge29 () =
    let _key = Random.randomBytes 16
    let gen = generate_mac _key
    let validate = validate_mac _key
    
    let message = "My validated message" |> Ascii.charToByte
    printfn "Original:"
    let mac = gen message
    
    // what's actually sha1'ed is "[key]My validated message[padding][size]"
    // given this, we can forge the sha1 of
    // "[key]My validated message[padding][size]someextracontent[padding'][size']"
    // where we pass "My validated message[padding][size]someextracontent" as message
    // to validate.
    
    // let's assume we know the key length is 16. The padding then looks like this
    let assumed_key_size = 16
    let message_size = (message |> Seq.length)
    let size_size = 8 // 64 bits
    let padding_size = 64 - ((assumed_key_size + message_size + size_size + 1) % 64)
    
    let original_blocks = Seq.concat [
        Seq.replicate assumed_key_size 0x00  // fill in empty key for easier comparison
        message
        Seq.singleton 0x80
        Seq.replicate padding_size 0x00
        Sha1.unmerge64 (uint64 ((message_size + assumed_key_size) * 8)) |> Seq.map int
    ]
    
    let original_padded = Seq.concat [ _key; message ] |> Seq.map uint8 |> Sha1.pad |> Seq.collect Sha1.unmerge32 |> Seq.map int 
    
    original_blocks |> Seq.skip assumed_key_size |> Hex.byteToHex |>
        should equal (original_padded |> Seq.skip assumed_key_size |> Hex.byteToHex)

    let original_blocks_size = assumed_key_size + message_size + size_size + 1 + padding_size 
    
    // we then add an extra block (64 bytes) containing
    // ";admin=true;\x01\x00....[size + 512]"
    let appended_value = ";admin=true;" |> Ascii.charToByte
    let appended_length = appended_value |> Seq.length
    
    let appended_block = Seq.concat [
        appended_value
        Seq.singleton 0x80
        Seq.replicate (64-8-1-(Seq.length appended_value)) 0x00
        Sha1.unmerge64 (uint64 ((original_blocks_size + appended_length) * 8)) |> Seq.map int    
    ]
    
    // verify we get the same last block using the regular padding logic
    let combined_padded = Seq.concat [ original_blocks; appended_value ] |> Seq.map uint8 |> Sha1.pad |> Seq.collect Sha1.unmerge32 |> Seq.map int
    appended_block |> Hex.byteToHex |>
        should equal (combined_padded |> Seq.skip 64 |> Hex.byteToHex)
    
    let appended_block_uint32 = appended_block |> Seq.map uint8 |> Seq.splitBlocks 4 |> Seq.map Sha1.merge32 |> Seq.toArray
    printfn "\nFake block:"
    let (a, b, c, d, e) = Sha1.process_chunk (mac[0], mac[1], mac[2], mac[3], mac[4]) appended_block_uint32
    
    // abcde is now the sha1 of (key + original text + original padding + new value)
    let combined_message = Seq.concat [
        original_blocks |> Seq.skip assumed_key_size
        appended_value
    ]
    
    printfn "\nCombined:"
    validate combined_message [a;b;c;d;e] |> should equal true
    
[<Test>]
let challenge30 () =
    "same shit different name" |> should equal "same shit different name"

let slowcompare (time: TimeSpan) x y =
    let rec sc x' y' =
        Thread.Sleep(time)
        match (x', y') with
        | (hx :: tx, hy :: ty) -> if hx = hy then sc tx ty else false
        | ([], []) -> true
        | _ -> false
    sc x y

type TimedResult<'a> =
    {
        Elapsed: TimeSpan
        Result: 'a
    }
    with static member op_Implicit(value: TimedResult<'a>): 'a = value.Result 
    
let timeit (func: Lazy<'a>): TimedResult<'a> =
    let sw = System.Diagnostics.Stopwatch()
    sw.Start()
    let result = func.Force()
    sw.Stop()
    
    {
        Elapsed = sw.Elapsed
        Result = result
    }

[<Test>]
let testslowcompare () =
    let waittime = TimeSpan.FromSeconds 1
    let test_sequence = seq { 1 .. 1 .. 10 } |> Seq.toList
    
    slowcompare (TimeSpan.FromSeconds 0) test_sequence test_sequence |> should equal true
    
    let results = seq { 0 .. 1 .. 4 } |>
                  Seq.map (fun x -> Seq.withreplace x 999 test_sequence) |>
                  Seq.map Seq.toList |>
                  Seq.map (fun x -> timeit (lazy (slowcompare waittime test_sequence x)))
                  
    results |> Seq.map (fun x -> x.Result) |> Seq.all ((=) false) |> should equal true
    let time_seconds = results |> Seq.map (fun x -> x.Elapsed.TotalSeconds |> Math.Round |> int)
    time_seconds |> should equal (seq { 1 .. 1 .. 5 })
    
    

    


type MyWebserver(key: bytearray) =
    let cts = new CancellationTokenSource()
    let conf = { defaultConfig with cancellationToken = cts.Token }
    let handleCheckSha1 param = OK $"{param}"
    let myHMAC = hmac.hmac_sha1 key
    
    let checkFileHmac delay file signature: bool =
        let computed_hmac = file |> Ascii.charToByte |> myHMAC
        slowcompare delay (computed_hmac |> List.ofSeq) (signature |> Hex.hexToByte |> List.ofSeq)
        
    let handleCheckHmac (ctx: HttpContext) =
        let file = ctx.request.queryParam "file" |> Choice.toOption
        let signature = ctx.request.queryParam "signature" |> Choice.toOption

        let delay =
            ctx.request.queryParam "delay"
            |> Choice.toOption
            |> Option.map int
            |> Option.defaultValue 0
            |> TimeSpan.FromMilliseconds
        
        match (file, signature) with
            | (Some(f), Some(s)) -> if checkFileHmac delay f s then
                                        OK "Success" ctx else
                                            RequestErrors.FORBIDDEN "incorrect signature" ctx
            | _ -> RequestErrors.BAD_REQUEST $"Missing either file {file} or signature {signature}" ctx

    let app = choose [
        GET >=> choose
            [
                path "/checkHmac" >=> handleCheckHmac
            ]
        (RequestErrors.NOT_FOUND "NOT FOUND")   
    ] 
    
    let listening, server = startWebServerAsync conf app
    
    do
        Async.Start(server, cts.Token)
        let stats = Async.RunSynchronously listening
        let s = stats[0] |> Option.get
        printfn $"Server started in {s.GetStartedListeningElapsedMilliseconds()} ms"

    interface IDisposable with
        member this.Dispose() = cts.Cancel();

    
module Request =
    let sendTimed request = timeit (lazy ( Request.send request ))

[<Test>]
let challenge31_prep () =
    let testkey = "key" |> Ascii.charToByte
    use server = new MyWebserver(testkey)
    
    let response = (http {
        GET "http://127.0.0.1:8080/checkHmac"
        query [
            "file", "The quick brown fox jumps over the lazy dog"
            "signature", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        ]
    } |> Request.sendTimed)
    
    Console.WriteLine(response.Elapsed);
    response.Result.statusCode |> should equal HttpStatusCode.OK
    response.Result |> Response.toString Option.None |> should equal "Success"
    
    
//[<Test>]
let challenge31 () =
    use server = new MyWebserver("key" |> Ascii.charToByte)
    let myfile = "The quick brown fox jumps over the lazy dog"
    
    let getResponseTime (signature: string) =
        (http {
            GET "http://127.0.0.1:8080/checkHmac"
            query [
            "file", myfile
            "signature", signature
            "delay", "50"
        ]
    } |> Request.sendTimed) |> (fun x -> x.Elapsed.TotalMilliseconds)
        
    // warm up web service
    ignore (getResponseTime "46b4ec586117154dacd49d664e5d63fdc88efb51")
    
    let checkByte index signature v =
        let newsig = Seq.withreplace index v signature
        newsig |> Hex.byteToHex |> getResponseTime
    
    let bestByteFor index signature =
        seq { 0 .. 1 .. 255 }
        |> Seq.maxBy (checkByte index signature)
    
    let folder signature index =
        let newbyte = bestByteFor index signature
        let newsig = Seq.withreplace index newbyte signature
        printf "Index %02d: byte %02x, complete signature %s\n" index newbyte (newsig |> Hex.byteToHex)
        newsig
    
    let computed_signature =
        seq { 0 .. 1 .. 19 }
        |> Seq.fold folder (List.replicate 20 0x00) 
    
    // the proof is in the pudding:
    let hexsig = computed_signature |> Hex.byteToHex
    let response = (http {
        GET "http://127.0.0.1:8080/checkHmac"
        query [
            "file", myfile
            "signature", hexsig
        ]
    } |> Request.sendTimed)
    
    response.Result.statusCode |> should equal HttpStatusCode.OK
    response.Result |> Response.toString Option.None |> should equal "Success"
    
    