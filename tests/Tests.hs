{-# LANGUAGE CPP #-}

module Main where

import Data.Monoid ((<>))
import System.FilePath.Posix ((</>), (<.>))
import System.Process (runCommand, waitForProcess)
import System.IO.Temp (withSystemTempDirectory)
import qualified Data.ByteString as SB

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck (Property, Arbitrary(..), elements)
import Test.QuickCheck.Monadic (monadicIO, run, assert)

import Crypto.PubKey.OpenSsh.Internal (OpenSshPublicKeyType(..),
                                       OpenSshPublicKey(..),
                                       parseOpenSshPublicKey)

type StrictByteString = SB.ByteString

instance Arbitrary OpenSshPublicKeyType where
    arbitrary = elements [OpenSshPublicKeyTypeRsa, OpenSshPublicKeyTypeDsa]

openSshPubKey :: OpenSshPublicKeyType -> IO StrictByteString
openSshPubKey t = withSystemTempDirectory base $ \dir -> do
    let path = dir </> typ
    let run = "ssh-keygen -t " <> typ <> " -N \"\" -f " <> path
    waitForProcess =<< runCommand run
    SB.readFile $ path <.> "pub"
  where
    base = "crypto-pubkey-openssh-tests"
    typ = case t of
        OpenSshPublicKeyTypeRsa -> "rsa"
        OpenSshPublicKeyTypeDsa -> "dsa"

testWithOpenSsh :: OpenSshPublicKeyType -> Property
testWithOpenSsh t = monadicIO $ do
    pub <- run $ openSshPubKey t
    assert $ check $ parseOpenSshPublicKey pub
  where
    check = case t of
        OpenSshPublicKeyTypeRsa -> \r -> case r of
            Right (OpenSshPublicKeyRsa _ _) -> True
            _                               -> False
        OpenSshPublicKeyTypeDsa -> \r -> case r of
            Right (OpenSshPublicKeyDsa _ _) -> True
            _                               -> False

main :: IO ()
main = defaultMain
    [
#ifdef OPENSSH
      testGroup "ssh-keygen" [ testProperty "decode" $ testWithOpenSsh
                             ]
#endif
    ]
