module Crypto.PubKey.OpenSsh.Encode.Tests
    ( tests
    ) where

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Crypto.PubKey.OpenSsh.Encode (expandInteger)

-- | In version 0.2.0 `expandInteger` function returns empty list for
-- integer 0.
testExpandInteger :: Integer -> Bool
testExpandInteger i = (> 0) $ length $ expandInteger i

tests :: Test
tests = testGroup "Crypto.PubKey.OpenSsh.Encode.Tests"
    [ testProperty "regression test expandInteger" testExpandInteger
    ]
