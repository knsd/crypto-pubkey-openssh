{-# LANGUAGE CPP #-}

module Main where

import Test.Framework (defaultMain)

import qualified Crypto.PubKey.OpenSsh.Encode.Tests
import qualified SshKeygen

main :: IO ()
main = defaultMain
    [ Crypto.PubKey.OpenSsh.Encode.Tests.tests
#ifdef OPENSSH
    , SshKeygen.tests
#endif
    ]
