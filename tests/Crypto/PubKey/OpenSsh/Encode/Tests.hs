module Crypto.PubKey.OpenSsh.Encode.Tests
    ( tests
    ) where

import Control.DeepSeq (deepseq)
import Data.Word (Word8)

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Crypto.PubKey.OpenSsh.Encode (fixZeroByte)

-- | In version 0.2.0 `fixZeroByte` function fails with empty input
testFixZeroByte :: [Word8] -> Bool
testFixZeroByte i = fixZeroByte i `deepseq` True

tests :: Test
tests = testGroup "Crypto.PubKey.OpenSsh.Encode.Tests"
    [ testProperty "regression test testFixZeroByte" testFixZeroByte
    ]
