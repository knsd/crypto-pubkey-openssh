{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString

import Test.Framework (Test, testGroup, defaultMain)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit (Assertion, assertFailure, (@=?))

import Crypto.PubKey.OpenSsh (OpenSshPublicKey, parseOpenSshPublicKey,
                              serializeOpenSshPublicKey)

dsaDefault1 = "ssh-dss AAAAB3NzaC1kc3MAAACBAL3TNYb4GQJju7JbshnD9JY+vJTRYvtMseZVRORwnK6shOiCGxYLwSqUgU60ucWCQgMKEgVuwkvkygzQbzO8OfD4lR9YL9QvpjM7fEbDI7es86CMhZGLlft3Dbly3YVlcgun4p15iVhgRNn6YqU1D1jbHkJwhh5eareVkqhKaETFAAAAFQD5dCToF/ApJTeakR0NjTzLFagXiQAAAIEAnjfQzZVIr+W0Id/yYzlSpxWasceB0BCciAcJoIcVid47zklz3ad22GA7lFqZwQn/6CUwxJQXbafAmtTGsXKiE7k71KaFn03Ul75DC+8mvccKyQoMzo97V+wyT3WoCs2hZ4eZ9HDNEYyPLRhCjOHnfD34sAdI5fF7wqOAsz4Lz60AAACAKxkNGhgV6iwCJxa1s3QIIGAEUobHKcKfy8ABUEojqup3RcH7ZbC5TWabrtoCCxnrMBG1Y9QXsytNbWc/OzplBVCSqNUTx8WmzgVmyBWhFAzWmrnX97/b7C1apPDZVgxehhXjJ3VEP56HL1vy4DE705wycF+Cq+EqDlaP0WqM0ac= max@max-Aspire-5820TG" :: ByteString

rsa1024 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCuFvQUmhwkRTb/neoFDQ3zsRV1Dd/g/eTwPYi9BcGe7WgZT0gKFdnwPB3TcP/W3QZWLU9UMDA74W6FP2cZ/dmsXrbaz3C5YbnCk5KiSMQSqEqeE90Pdl1/GYUmIILWIky7Juz0V6XDBZ9PTr/S2SBFcckGSi4YrqzcQwnn/l6kNw== max@max-Aspire-5820TG" :: ByteString

rsaDefault = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDArX1miiWFXODbVen4lQvnv64nzD7DZT3c9J7UT+sPc5OwYlB2GFwKwsOwNfq7Lzi3eE9pZ83v9FtSES0vgjqbQCnLhHBUhO70mzXvx7NV0LSirB25j6fXP/lMrh/g3EFVMdFbK2jaZH1Nsdy4pmNeCi2N3juvEZ99hHB4i1dMHEDT4YV6atYmMeRzcHTKsxzL3GFUMy3BjURMtXJZacPLeVGo50anzDidtQP8MApZ+swrdGI2VveKouq7APjmye/Td0SiO6MU3udpndAQBpM7BiR353+bMcrirE1wUtrV60439B+6mbi1c0S7i2sxdJpq1fp826h8EnQZfRGWrECT max@max-Aspire-5820TG" :: ByteString

dsaDefault2 = "ssh-dss AAAAB3NzaC1kc3MAAACBAPUvGfsyk9jeiKAuU4wOIdyPj918lWJK8EcSF5v/SEmjX+kp+4xy7arK5wkPNH6ykPKwXPcq1SGiVhQvALjqxS7G+bTL+M6e9FX0OWoAJ3lfOOMjjfcLHuyLzuTecsrBUHtJ1TcHe8WhEKi6fDyHdWHFM8QibUY3lumDuVjo6MqJAAAAgQCk/UaFKANtUMM1SmqTgmfMugtNEMNnTw7UBfrd4QwMwbafwAy2K26xAMdOTW7u6ycf4ZO3IMyR+zxOLsLz24uv7QbKZ/X/uc2nFzTepEWyZaVSOdRdxEQnEGth/ox/0PcRuBGgn6cSqaVaBaW0uK9HpUEngiEMmFnHA9pV6RsylQAAABUAlGllRN22btm/70hlT80kWZNRm30AAACBAJkd0FHUTzDOO2aL+08E+37rLCGA62R8t8RNbPcACC8okPDcQzpEBG6Zd8xjXwPbVgQLZW3v6xjcKRlWXWriuGeXh5J8Pz5Jq+QZeywWRidum+AFS21DtkqmZI0T+uRSgNS9VnrXE1MAPyDZJYWOoLPGECGK3BI/pdFfC8M10fZA max@max-Aspire-5820TG" :: ByteString

parse :: ByteString -> Either String OpenSshPublicKey
parse = parseOpenSshPublicKey

serial :: OpenSshPublicKey -> ByteString
serial = serializeOpenSshPublicKey

testKey :: ByteString -> Assertion
testKey key = case parse key of
    Right parsedKey -> (serial parsedKey) @=? key
    _ -> assertFailure "unparsed Key"

tests :: Test
tests = testGroup "Crypto.PubKey.OpenSsh.Tests"
    [ testCase "Test DSA first" $ testKey dsaDefault1
    , testCase "Test DSA another" $ testKey dsaDefault2
    , testCase "Test RSA" $ testKey rsaDefault
    , testCase "Test RSA 1024 bits length" $ testKey rsa1024
    ]

main :: IO ()
main = defaultMain [tests]
