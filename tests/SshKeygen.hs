{-# LANGUAGE TypeSynonymInstances #-}

module SshKeygen where

import Data.Monoid ((<>))
import System.FilePath.Posix ((</>), (<.>))
import System.Process (runCommand, waitForProcess)
import System.IO.Temp (withSystemTempDirectory)
import qualified Data.ByteString.Char8 as SB

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck (Property, Arbitrary(..), elements, suchThat)
import Test.QuickCheck.Monadic (monadicIO, run, assert)

import Crypto.PubKey.OpenSsh.Types (OpenSshKeyType(..), OpenSshPublicKey(..),
                                    OpenSshPrivateKey(..))
import Crypto.PubKey.OpenSsh (encodePublic, decodePublic,
                              encodePrivate, decodePrivate)

import qualified Crypto.PubKey.OpenSsh.Encode.Tests

type StrictByteString = SB.ByteString
type PrivateKey = StrictByteString
type PublicKey = StrictByteString

instance Arbitrary OpenSshKeyType where
    arbitrary = elements [OpenSshKeyTypeRsa, OpenSshKeyTypeDsa]

openSshKeys :: OpenSshKeyType -> IO (PrivateKey, PublicKey)
openSshKeys t = withSystemTempDirectory base $ \dir -> do
    let path = dir </> typ
    let run = "ssh-keygen -t " <> typ <> " -N \"\" -f " <> path
    waitForProcess =<< runCommand run
    priv <- SB.readFile $ path
    pub <- fmap SB.init $ SB.readFile $ path <.> "pub"
    return (priv, pub)
  where
    base = "crypto-pubkey-openssh-tests"
    typ = case t of
        OpenSshKeyTypeRsa -> "rsa"
        OpenSshKeyTypeDsa -> "dsa"

testWithOpenSsh :: OpenSshKeyType -> Property
testWithOpenSsh t = monadicIO $ do
    (priv, pub) <- run $ openSshKeys t
    assert $ checkPublic (decodePublic pub) pub
    assert $ checkPrivate (decodePrivate priv) priv
  where
    checkPublic = case t of
        OpenSshKeyTypeRsa -> \r b -> case r of
            Right k@(OpenSshPublicKeyRsa _ _) ->
                encodePublic k == b
            _                                 -> False
        OpenSshKeyTypeDsa -> \r b -> case r of
            Right k@(OpenSshPublicKeyDsa _ _) ->
                encodePublic k == b
            _                                 -> False
    checkPrivate = case t of
        OpenSshKeyTypeRsa -> \r b -> case r of
            Right k@(OpenSshPrivateKeyRsa _) ->
                encodePrivate k == b
            _                                 -> False
        OpenSshKeyTypeDsa -> \r b -> case r of
            Right k@(OpenSshPrivateKeyDsa _ _) ->
                encodePrivate k == b
            _                                 -> False

tests :: Test
tests = testGroup "SshKeygen"
    [ testProperty "decode/encode" $ testWithOpenSsh
    ]
