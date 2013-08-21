{-# LANGUAGE CPP #-}

module Main where

import Test.Tasty (defaultMain, testGroup)

import qualified Crypto.PubKey.OpenSsh.Encode.Tests
import qualified Crypto.PubKey.OpenSsh.Decode.Tests
import qualified SshKeygen

main :: IO ()
main = defaultMain $ testGroup "Tests"
    [ Crypto.PubKey.OpenSsh.Encode.Tests.tests
    , Crypto.PubKey.OpenSsh.Decode.Tests.tests
#ifdef OPENSSH
    , SshKeygen.tests
#endif
    ]
