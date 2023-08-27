namespace cryptopals

open System.Numerics
open System.Security.Cryptography

module rsa =
    let randomprime (keysize: int) =
        use r = RSA.Create(keysize)
        r.ExportParameters(true).P |> Seq.map int |> Seq.toBigintBe
        
    let rec egcd (a: bigint) (b: bigint) =
        if (a = bigint 0)
        then (b, bigint 0, bigint 1)
        else
            let (g, x, y) = egcd (b % a) a
            (g, y - (b / a) * x, x)

    let invmod (a: bigint) (m: bigint) =
        let (gcd, x, _) = egcd a m
        if (gcd = bigint 1)
        then Some ((x % m + m) % m)
        else None
        
    let rec randomprimeforexponent exponent keysize =
        let r = randomprime keysize
        match (invmod exponent (r - (bigint 1))) with
               | Some _ -> r
               | _ -> randomprimeforexponent exponent keysize

    type Rsa(?p': bigint, ?q': bigint) =
        let e = bigint 3
        let p = p' |> Option.defaultWith (fun () -> randomprimeforexponent e 1024)
        let q = q' |> Option.defaultWith (fun () -> randomprimeforexponent e 1024)
        let n = (p * q)
        let et = (p-(bigint 1)) * (q- (bigint 1))
        let d = invmod e et |> Option.get
        let pub' = (e, n)
        let priv' = (d, n)
        
        member this.pub = pub'
        
        member this.encrypt m = BigInteger.ModPow(m, e, n)
        member this.decrypt c = BigInteger.ModPow(c, d, n)

        
