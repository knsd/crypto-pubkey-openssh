{-# LANGUAGE OverloadedStrings #-}
module Crypto.PubKey.OpenSsh.Decode.Tests
    ( tests
    ) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (testProperty, once)

import Crypto.PubKey.OpenSsh.Decode (decodePublic, decodePrivate)
import Data.ByteString.Char8 ()

testDecodeRSAPublic :: Bool
testDecodeRSAPublic =
    case decodePublic rsaPub of
        Left _  -> False
        Right _ -> True
 where
  rsaPub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtuy+p1/IHUtofNeUg6Ex2Sc3f0B+97VsfAq65pyKvAAqAtZpR96Vr35hbaNEb+j3fpAXjrxouM87q5KksWD+0qFWNhDv7rBg6ENQJNLf5lfssiFacrVv1/SG2UP8VDkCMxpJyzcHE5ajmSzcjEFoerRudV2g05PPlw4fNyuhVaMQjNUejg+17CUPS8e7TxUoRvnVuBVSMezMn11n81djakzuit7nXj1L7WVqNHtAlbstK2aDdCB3yBOtOwBQVwvFwQfHpQ8hwrYoKAXPw3YTd9sPTtJ0qz0cZH89t7redHABRhOWdf7+cm0LpubqwWvv0SLlFRMwefoMsGcnJ6E7P tommd@Vodka"

testDecodeRSAPrivate :: Bool
testDecodeRSAPrivate =
    case decodePrivate rsaPriv of
        Left _  -> False
        Right _ -> True
 where
 rsaPriv = "-----BEGIN RSA PRIVATE KEY-----\n\
\MIIEpAIBAAKCAQEAw6s7oDCoXjEkrLDRVZDyWLVaiqxZyOTA33TyGSELv9ZiQzkr\n\
\ti+AOyuTWkmZjHYdLDWBYYQvwEjufzneHvNLw87/1zsQrd6ZPUwEOkh0RqG9mxoV\n\
\JFgpruzKoG6BNgnUti/S9idErit+XEx9ff8bmmjawdC10czAdL3zCpZaEXw4JAwC\n\
\sgQB1J1/Mw4cnzMqKyxPtSPZjhiZZ6y2bVCfNfnOZ9dvIDa/unEWlFSDPjX0+zSM\n\
\mjRzDoE04jtoAI0v3iynZ26kea+YU4oni2MQ7EL4Y1CmLAWm4/9APhf3Xt0EJOIt\n\
\Ngv1j2468+8WF5aTEitb8D2ZRFYPiLWMaJlhGwIDAQABAoIBAQCWAPXLDsJkw4P8\n\
\J+mzkVVZEF8DJLIIQuZh6MOY5C6fuPjH1FJgbvX9ZqCmfPoMJpiixboUSkRZQxAj\n\
\1Pcl/xq8WDrmg897m8UaquYq0FTjuScketBudnAuPDXy3ASOqua5bNxr/Rq383wB\n\
\wloKd8Jvk6bxItHgrvl0BhMGsNEHyT36SXmc7HsgCzifuXMo5E3uqTGP/+wLWCRy\n\
\NO+AqStSjQbQZtLVOvNdQYknv+uqm/m5LyO1Vi2pPl0vEgpwiq4C/8W+YT2ya3dz\n\
\QfG+Fsewu5WDdHTBgTN4F/p2tgG6Zg+fdfRkF2NNwJXiGb1TTmR1IMZtzqDQ5mys\n\
\dk40xuAxAoGBAOTMhUpINw2rSaduEWAxnSAZFMAIozKBOJD1Q2+kYbYMHPOPN+CN\n\
\NCUrWpEiFa+vM+BIrQsG6M7Nb9VmefOKuS7vetIUYWsJ2hO8oX2+8ZiPcBwU3izX\n\
\wAoGq0yeUaG4yGZUrkP2Gfm+jUdj/AoGOnG9pd/CYDevVNnOSyWko8RVAoGBANru\n\
\Zupv8fIXDcnqYGBAbHpBQkojAzccBHxyE/4BUJlFIZWDAMem50op49SsF6gKrxtO\n\
\IvXb1+58axGza84F7cXmQgR0nV8AXMzBlI31HyvftMv8Yb1h+oXbjCFI99lMz6/F\n\
\jkCSzoiLGo0NAEmqRb4TThSjj8vfiw+zxsllQH+vAoGAFmKcN+RQ3pl/n035jTvN\n\
\b7KEgTVXIj3aVvRoIKgolzMgMgQ1J1cpXuma9tAq5wFxReRWadnHNVSMOIjKLbXI\n\
\4Hq1vZAY5+wS1hOCiVcBNDf0dArmoeSJ+XElmV10ByqZEMoAMs4FRJYMJIv3wNNT\n\
\LIWtkPLnjwssdhLk703oZ/ECgYB/4JCsjwa7aUvcjNIOZpL2NfgKZbkTD4JvThLv\n\
\YsU5QXAEbKif9ZVTdHRnXL3Uoaj2QgWZpffSjUnc5PgrNrtTxNL610K0ovmRf+DN\n\
\qkey0NBB9gEBJaG3Xi3To1Nh0cPd337fqOCKUPYJPXbVkGd8Rrpsw7zSUJhha5jJ\n\
\OiMacQKBgQCxDCTOUqDksmXkDutXi/f/dMIwfMXaNuTc3ectyaBC05+0B10uLfnv\n\
\7jurNd89OFTHsu7CLfbwDzu+Q+GWTWemUk2ieq9z0Ct5aIzjxoALNnKiu5pH1YDH\n\
\Mf6ApFppkCpTkQ0sEERn0zH/hNQct1cwflfQi7JN+3GGax7oySmQRQ==\n\
\-----END RSA PRIVATE KEY-----"

testDecodeDSAPublic :: Bool
testDecodeDSAPublic =
    case decodePublic dsaPub of
        Left _  -> False
        Right _ -> True
 where
  dsaPub = "ssh-dss AAAAB3NzaC1kc3MAAACBALco1Yeq0uPETFRf72VbmH+sMttQMbs1GRF+9vbkI7GJZtaRCE2+jtVSiFXDBm4Yuxf+pqvdQ6Jl1X/zuED/YzN2GIVhHMzy12KQ27E8B63vIP/hhLaYv7Tw00yE7HzxBrbx4rfdkPguam0Mjzqhck4cwVKsKhuSinaGTwqMF+KRAAAAFQCziBsxBGOF2YDzsXnBs+Jv0p2GewAAAIEAiCaFUZcLEO5WTAi/lQNo42ZyXP2rl1jeugPVCtDSWhSEHU1EIJcmmCx//ofaOz/X2uJAv15ZjLY8xZW41N2wHA64mhjaXzBBUeVqAOgoYW8dQOo2XNFmU7idWsYxhsUUknWDf9A6v4blUgQNHn1u8c4Y3xcfCEHfZB6om6XA7aAAAACAI3H1hNNXWzd5Fuqpj1ZeUKFAOfFbYeD3XBIKwwMPdrVZW/PMJ3s+Ic90V0paKBA0+Sgvg+EHWK213+zEp29+lL50Nne7jh//smQ0zBKMiRre7iZ+rEDM4nWZOM3vzClfgilTDkkQ4TCjz7yMm21ZqApt+Lq5uNOK6DJB4PszCwI= tommd@Vodka"

testDecodeDSAPrivate :: Bool
testDecodeDSAPrivate =
    case decodePrivate dsaPriv of
        Left _  -> False
        Right _ -> True
 where
  dsaPriv = "-----BEGIN DSA PRIVATE KEY-----\n\
\MIIBuwIBAAKBgQC3KNWHqtLjxExUX+9lW5h/rDLbUDG7NRkRfvb25COxiWbWkQhN\n\
\vo7VUohVwwZuGLsX/qar3UOiZdV/87hA/2MzdhiFYRzM8tdikNuxPAet7yD/4YS2\n\
\mL+08NNMhOx88Qa28eK33ZD4LmptDI86oXJOHMFSrCobkop2hk8KjBfikQIVALOI\n\
\GzEEY4XZgPOxecGz4m/SnYZ7AoGBAIgmhVGXCxDuVkwIv5UDaONmclz9q5dY3roD\n\
\1QrQ0loUhB1NRCCXJpgsf/6H2js/19riQL9eWYy2PMWVuNTdsBwOuJoY2l8wQVHl\n\
\agDoKGFvHUDqNlzRZlO4nVrGMYbFFJJ1g3/QOr+G5VIEDR59bvHOGN8XHwhB32Qe\n\
\qJulwO2gAoGAI3H1hNNXWzd5Fuqpj1ZeUKFAOfFbYeD3XBIKwwMPdrVZW/PMJ3s+\n\
\Ic90V0paKBA0+Sgvg+EHWK213+zEp29+lL50Nne7jh//smQ0zBKMiRre7iZ+rEDM\n\
\4nWZOM3vzClfgilTDkkQ4TCjz7yMm21ZqApt+Lq5uNOK6DJB4PszCwICFAG6JRA/\n\
\iyaf5dPPUem5PxQeKx1b\n\
\-----END DSA PRIVATE KEY-----"

tests :: TestTree
tests = testGroup "Crypto.PubKey.OpenSsh.Decode.Tests"
    [ testProperty "Decode Public RSA" $ once testDecodeRSAPublic
    , testProperty "Decode Private RSA" $ once testDecodeRSAPrivate
    , testProperty "Decode Public DSA" $ once testDecodeDSAPublic
    , testProperty "Decode Private DSA" $ once testDecodeDSAPrivate
    ]
