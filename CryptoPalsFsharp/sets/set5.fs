module set5

open System
open System.Collections.Generic
open System.Net
open System.Numerics
open System.Security.Cryptography
open System.Threading
open Microsoft.FSharp.Collections
open Microsoft.FSharp.Control
open NUnit.Framework
open FsUnit
open cryptopals

let nistprime: bigint =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
        |> Hex.hexToByte
        |> Seq.toBigintBe

[<Test>]
let challenge33_smallint () =
    let p = 37
    let g = 5
    
    let a = 2
    let A = (pown g a) % p
    
    let b = 5
    let B = (pown g b) % p
    
    let s_a = (pown B a) % p
    let s_b = (pown A b) % p
    
    s_a |> should equal (9765625 % p) // 5^(2*5)
    s_a |> should equal s_b
    



[<Test>]
let challenge33_bigint () =
    let p: bigint = nistprime
    let g: bigint = 2 |> BigInteger
    
    let a = Random.randomBigInt 1024
    
    let A = BigInteger.ModPow(g, a, p)
    
    let b = Random.randomBigInt 1024
    let B = BigInteger.ModPow(g, b, p)
    
    let s_a = BigInteger.ModPow(B, a, p)
    let s_b = BigInteger.ModPow(A, b, p)
    
    let s_a_hex = s_a.ToByteArray(true, true) |> Seq.map int |> Hex.byteToHex
    let s_b_hex = s_b.ToByteArray(true, true) |> Seq.map int |> Hex.byteToHex
    
    s_a_hex |> should equal s_b_hex


type DiffieHellman(p: bigint, g: bigint) =
    let a = Random.randomBigInt 1024
    member this.A: bigint = BigInteger.ModPow(g, a, p)
    member this.Authenticate (B: bigint) =
        let s = BigInteger.ModPow(B, a, p)
        let key =
            s.ToByteArray(true, true)
            |> Seq.map int
            |> Sha1.hash
            |> Seq.collect Sha1.unmerge32
            |> Seq.map int
            |> Seq.take 16
        key

type Partner(shared_key: seq<int>) =
     member this.encrypt content =
         let iv = Random.randomBytes(16)
         Aes.encryptCbcPkcs7 shared_key iv content |> Seq.append iv
         
     member this.decrypt enc =
        let iv = enc |> Seq.take 16
        let enc = enc |> Seq.skip 16
        Aes.decryptCbcPkcs7 shared_key iv enc
        
     member this.echo enc: seq<int> =
         enc
         |> this.decrypt
         |> Option.defaultValue Seq.empty
         |> this.encrypt

     member this.secretMessage (): seq<int> =
         "My secret message"
         |> Ascii.charToByte
         |> this.encrypt
         
     member this.validate enc =
         enc
         |> this.decrypt
         |> Option.defaultValue Seq.empty
         |> Ascii.byteToChars
         |> should equal "My secret message"
    
type InitialServer() =
    member this.auth (p, g, A) =
        let dh = DiffieHellman(p, g)
        let shared_key = dh.Authenticate(A)
        (Partner(shared_key), (p, g, dh.A))

type InitialClient() =
    let p: bigint = nistprime
    
    let g: bigint = 2 |> BigInteger
    let dh = DiffieHellman(p, g)
    
    member this.public_key = (p, g, dh.A)
    member this.auth (p, g, partner_public) = Partner(dh.Authenticate partner_public)
    
[<Test>]
let challenge34_nomitm() =
    let server = InitialServer()
    let client = InitialClient()
    
    let client_public = client.public_key
    let (server, server_public) = server.auth client_public
    let client = client.auth server_public
    
    let enc_1 = client.secretMessage()
    let enc_2 = server.echo enc_1
    client.validate enc_2
    
[<Test>]
let challenge34_mitm() =
    let server = InitialServer()
    let client = InitialClient()
    
    let (p, g, A) = client.public_key
    let (server, (p', g', B)) = server.auth (p, g, p)
    let client = client.auth (p', g', p)
    
    let enc_1 = client.secretMessage()
    let enc_2 = server.echo enc_1
    client.validate enc_2
    
    // with `p` as public key, S = (p^a) mod p = (p^b) mod p = 0
    // thus
    let key =
        (bigint 0).ToByteArray(true, true)
        |> Seq.map int
        |> Sha1.hash
        |> Seq.collect Sha1.unmerge32
        |> Seq.map int
        |> Seq.take 16
    let mitm = Partner(key)

    enc_1 |> mitm.decrypt |> Option.defaultValue Seq.empty |> Ascii.byteToChars |> should equal "My secret message"
    enc_2 |> mitm.decrypt |> Option.defaultValue Seq.empty |> Ascii.byteToChars |> should equal "My secret message"


type Registration =
    { I: string
      Salt: seq<int>
      X: bigint }

    static member Hash P salt =
        Seq.append salt (P |> Ascii.charToByte)
            |> Sha256.hash
            |> Seq.toBigintBe
    
    static member Create I P =
        let salt = Random.randomBytes 16
        let hash = Registration.Hash P salt
        {I=I; Salt=salt; X=hash}

let biginthash (bi1: bigint) (bi2: bigint) =
    Seq.append (bi1.ToByteArray(true,true)) (bi2.ToByteArray(true, true))
            |> Seq.map int
            |> Sha256.hash
            |> Seq.toBigintBe
    
type Server36() =
    let users = Dictionary<string, Registration>()
    member this.register I P =
        users.Add(I, Registration.Create I P)
    
    member this.authenticate I (p: bigint, g: bigint, k: bigint, A: bigint) =
        let inline ( |^| ) x y = BigInteger.ModPow(x, y, p)
        
        let b = Random.randomBigInt 1024

        let reg = users[I]
        
        printfn $"server: p={p}"
        printfn $"server: g={g}"
        printfn $"server: k={k}"
        printfn $"server: A={A}"
            
        printfn $"server: X={reg.X}"
        
        
        let v = g |^| reg.X
        printfn $"server: v=g^X={v}"
        
        let B = g |^| b
        printfn $"server: B={B}"
        let B' = (B + k * v) % p
        printfn $"server: B'=(B + kv)={B'}"
        
        let u = biginthash A B'            
        printfn $"server: u=SHA256(A || B')={u}"
        
        printfn $"server: A^b = {A}^{b} = {A |^| b}"
        printfn $"server: g^xub = {g}^({reg.X}*{u}*{b}) = {g |^| (reg.X*u*b)}"
 
        let S = (A * (v |^| u)) |^| b
        printfn $"server: S=(A * v^u)^b = {S}"
        let K = S.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
        let correct_hmac = hmac.hmac_sha1 K reg.Salt
        
        (reg.Salt, B'), correct_hmac
        
type Client36(I:string, P: string) =
    let p = nistprime
    let g = bigint 2
    let k = bigint 3
    let a = Random.randomBigInt 1024
    let A: bigint = BigInteger.ModPow(g, a, p)
    
    member this.InitParams = (I, (p, g, k, A))

    member this.Auth (salt, B': bigint) =
        let inline ( |^| ) x y = BigInteger.ModPow(x, y, p)

        let X = Registration.Hash P salt
        printfn $"client: X={X}"

        let v = g |^| X
        printfn $"client: v={v}"
        
        let u = biginthash A B'
        printfn $"client: u={u}"

        let B = ((B' - k*v) % p + p) % p
        printfn $"client: B = B'-kv = {B}"
        
        printfn $"client: g^ab = {B |^| a}"
        printfn $"client: g^xub = {B |^| (X*u)}"
        
        let S = B |^| (a + u * X)
        printfn $"client: S = (gb)^(a + uX) = {B}"
        
        let K = S.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
        hmac.hmac_sha1 K salt

[<Test>]
let challenge36 () =
    let srv = Server36()
    srv.register "valhallasw" "mysecretpassword"
    
    let cli = Client36("valhallasw", "mysecretpassword")
    
    let handshake, correct_hmac = srv.authenticate <|| cli.InitParams
    cli.Auth handshake |> Hex.byteToHex |> should equal (correct_hmac |> Hex.byteToHex)

    let cli = Client36("valhallasw", "noymysecretpassword")
    
    let handshake, correct_hmac = srv.authenticate <|| cli.InitParams
    cli.Auth handshake |> Hex.byteToHex |> should not' (equal (correct_hmac |> Hex.byteToHex))

[<Test>]
let challenge37 () =
    let srv = Server36()
    srv.register "valhallasw" "mysecretpassword"
    
    // A = 0 -> S = 0
    // A a multiple of P -> S = 0
    for A in [bigint 0; nistprime; (bigint 2) * nistprime] do
        let handshake, correct_hmac = srv.authenticate "valhallasw" (nistprime, bigint 2, bigint 3, A)

        let S = bigint 0
        let K = S.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
        let my_hmac = hmac.hmac_sha1 K (fst handshake)
        
        my_hmac |> Hex.byteToHex |> should equal (correct_hmac |> Hex.byteToHex)
    
[<Test>]
let challenge38 () =
    let inline ( |^| ) x y = BigInteger.ModPow(x, y, nistprime)
    let g = bigint 2
    let k = bigint 3
    let a = Random.randomBigInt 1024
    let b = Random.randomBigInt 1024
    let u = Random.randomBigInt 128

    let password = "mypassword" |> Ascii.charToByte
    
    // server
    let salt = Random.randomBytes 16
    let x =
        Seq.append salt password
        |> Sha256.hash
        |> Seq.toBigintBe
    let v = g |^| x
    
    // client
    let I = "valhallasw"
    let A = g |^| a
    // C->S I,A
    
    // server
    let B = g |^| b
    // S->C salt, B, u
    
    // client
    let x = x
    let S_c = B |^| (a + u * x)
    let K_c = S_c.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
    
    // server
    let S_s = (A * (v |^| u)) |^| b
    let K_s = S_s.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
    
    // client
    let H_c = hmac.hmac_sha1 K_c salt |> Hex.byteToHex
    
    // server
    let H_s = hmac.hmac_sha1 K_s salt |> Hex.byteToHex
    
    H_c |> should equal H_s
    
    
    // We are an evil server, so we know all values above
    // For an arbitrary password, we can compute what the client would have sent:    
    let password_to_hmac' g' A' u' b' password' =
        let x' =
            Seq.append salt (password' |> Ascii.charToByte)
            |> Sha256.hash
            |> Seq.toBigintBe
        let v' = g' |^| x'
        let S_s' = (A' * (v' |^| u')) |^| b'
        let K_s' = S_s'.ToByteArray(true, true) |> Seq.map int |> Sha256.hash
        hmac.hmac_sha1 K_s' salt |> Hex.byteToHex
    let password_to_hmac = password_to_hmac' g A u b

    let maybepasswords = [
        "cookie"
        "crypto"
        "house"
        "mypassword"
        "supersecure"
    ]
    
    maybepasswords |> Seq.where (password_to_hmac >> (=) H_c) |> Seq.first |> should equal (Some "mypassword")
    
    
[<Test>]
let test_prime_extraction() =
    let r = (using (RSA.Create(1024)) (fun x -> x.ExportParameters(true)))
    let p = r.P |> Seq.map int |> Seq.toBigintBe
    let q = r.Q |> Seq.map int |> Seq.toBigintBe
    let n = r.Modulus |> Seq.map int |> Seq.toBigintBe
    
    (p * q) |> should equal n

[<Test>]
let test_modinv() =
    rsa.invmod (bigint 17) (bigint 3120) |> should equal (Some (bigint 2753))
    
[<Test>]
let challenge39() =
    let rsa_obj = rsa.Rsa((bigint 11), (bigint 17))
    let encrypted = rsa_obj.encrypt (bigint 42)
    
    encrypted |> should equal (bigint ((42 * 42 * 42) % (17 * 11)))
    
    let rsa_obj = rsa.Rsa()

    let mystring = "Hello!"
    let mystring_bi = mystring |> Ascii.charToByte |> Seq.toBigintBe
    
    mystring_bi |> rsa_obj.encrypt |> rsa_obj.decrypt |> Seq.fromBigintBe |> Ascii.byteToChars |> should equal "Hello!"

let CubicRoot (value: bigint) =
    let inline ( |^| ) x y = BigInteger.ModPow(x, y, value)
    let inline ( |/| ) x y = BigInteger.Divide(x, y)
     
    let rec InvPowImpl (estimate: bigint) (maxiter: int) =
        let error = (estimate ** 3) - value
        let slope = (bigint 3) * ((estimate - (bigint 1)) ** 2)
        let newestimate = estimate - (error |/| slope)
        
        printfn $"{maxiter}: estimate {estimate} -> {estimate ** 3}, error {error}, slope {slope}, newestimate {newestimate}"

        if (estimate = newestimate) || (maxiter = 0)
        then estimate
        else InvPowImpl newestimate (maxiter-1)
    
    let initial = (bigint 2 |^| (BigInteger.Log2(value) |/| 3))
    printfn $"Estimating cubic root of {value}, initial guess {initial}"
    InvPowImpl initial 10

[<Test>]
let challenge40() =
    let message = "Hello!" |> Ascii.charToByte |> Seq.toBigintBe
    printfn $"Hello!  ==  {message}"
    let get_ct_and_pubkey() =
        let rsa_obj = rsa.Rsa()
        (rsa_obj.encrypt message, rsa_obj.pub)
        
    let (c0, (e0, n0)) = get_ct_and_pubkey ()
    let (c1, (e1, n1)) = get_ct_and_pubkey ()
    let (c2, (e2, n2)) = get_ct_and_pubkey ()
    
    let ms0 = n1 * n2
    let ms1 = n0 * n2
    let ms2 = n0 * n1
    
    let result =
        (c0 * ms0 * (rsa.invmod ms0 n0 |> Option.get)) +
        (c1 * ms1 * (rsa.invmod ms1 n1 |> Option.get)) +
        (c2 * ms2 * (rsa.invmod ms2 n2 |> Option.get))
        
    (result % (n0 * n1 * n2)) |> CubicRoot |> Seq.fromBigintBe |> Ascii.byteToChars |> should equal "Hello!"
    
