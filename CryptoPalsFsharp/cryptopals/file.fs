module File

open System.IO
open System.Reflection

let getAllLines (stream : Stream) : string list =
    let rec r (reader : StreamReader) =
        let line = reader.ReadLine()
        if line = null
        then []
        else line :: (r reader)
    
    using (new StreamReader(stream)) r

let private readDataFile (filename: string) =
    let executingAssembly = Assembly.GetExecutingAssembly()
    let convertedFilename = filename.Replace("\\", ".").Replace("/", ".").Replace("-", "_")
    use stream = executingAssembly.GetManifestResourceStream(executingAssembly.GetName().Name + "." + convertedFilename)
    getAllLines stream

let private readWithPrefix prefix fileName = (+) prefix fileName |> readDataFile
    
let readChallengeData = readWithPrefix "sets/challenge-data/"

let readTestData = readWithPrefix "tests/resources/"