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
                                       parseOpenSshPublicKey,
                                       serializeOpenSshPublicKey)

type StrictByteString = SB.ByteString

instance Arbitrary OpenSshPublicKeyType where
    arbitrary = elements [OpenSshPublicKeyTypeRsa, OpenSshPublicKeyTypeDsa]

openSshPubKey :: OpenSshPublicKeyType -> IO StrictByteString
openSshPubKey t = withSystemTempDirectory base $ \dir -> do
    let path = dir </> typ
    let run = "ssh-keygen -t " <> typ <> " -N \"\" -f " <> path
    waitForProcess =<< runCommand run
    fmap SB.init $ SB.readFile $ path <.> "pub"
  where
    base = "crypto-pubkey-openssh-tests"
    typ = case t of
        OpenSshPublicKeyTypeRsa -> "rsa"
        OpenSshPublicKeyTypeDsa -> "dsa"

testWithOpenSsh :: OpenSshPublicKeyType -> Property
testWithOpenSsh t = monadicIO $ do
    pub <- run $ openSshPubKey t
    assert $ check (parseOpenSshPublicKey pub) pub
  where
    check = case t of
        OpenSshPublicKeyTypeRsa -> \r b -> case r of
            Right k@(OpenSshPublicKeyRsa _ _) ->
                serializeOpenSshPublicKey k == b
            _                                 -> False
        OpenSshPublicKeyTypeDsa -> \r b -> case r of
            Right k@(OpenSshPublicKeyDsa _ _) ->
                serializeOpenSshPublicKey k == b
            _                                 -> False

main :: IO ()
main = defaultMain
    [
#ifdef OPENSSH
      testGroup "ssh-keygen" [ testProperty "decode" $ testWithOpenSsh
                             ]
#endif
    ]
