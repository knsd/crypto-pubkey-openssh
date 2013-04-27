{-# LANGUAGE CPP #-}

module Main where

import Test.Framework (defaultMain)

import qualified Crypto.PubKey.OpenSsh.Encode.Tests
import qualified Crypto.PubKey.OpenSsh.Decode.Tests
import qualified SshKeygen

main :: IO ()
main = defaultMain
    [ Crypto.PubKey.OpenSsh.Encode.Tests.tests
    , Crypto.PubKey.OpenSsh.Decode.Tests.tests
#ifdef OPENSSH
    , SshKeygen.tests
#endif
    ]
