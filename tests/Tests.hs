{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Main where

import Data.Monoid ((<>))
import System.FilePath.Posix ((</>), (<.>))
import System.Process (runCommand, waitForProcess)
import System.IO.Temp (withSystemTempDirectory)
import qualified Data.ByteString.Char8 as SB

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck (Property, Arbitrary(..), elements, suchThat)
import Test.QuickCheck.Monadic (monadicIO, run, assert)

import Crypto.PubKey.OpenSsh.Types (OpenSshKeyType(..), Passphrase,
                                    OpenSshPublicKey(..), OpenSshPrivateKey(..))
import Crypto.PubKey.OpenSsh (encodePublic, decodePublic,
                              encodePrivate, decodePrivate)

type StrictByteString = SB.ByteString
type PrivateKey = StrictByteString
type PublicKey = StrictByteString

instance Arbitrary OpenSshKeyType where
    arbitrary = elements [OpenSshKeyTypeRsa, OpenSshKeyTypeDsa]

instance Arbitrary Passphrase where
    arbitrary = fmap SB.pack $
        arbitrary `suchThat` all check
      where
        check = (`elem` ['A'..'Z'] ++ ['a'..'z'] ++ ['0'..'9'])

openSshKeys :: OpenSshKeyType -> Maybe Passphrase -> IO (PrivateKey, PublicKey)
openSshKeys t mbPass = withSystemTempDirectory base $ \dir -> do
    let path = dir </> typ
    let run = "ssh-keygen -t " <> typ <> " -N " <> pass <> " -f " <> path
    waitForProcess =<< runCommand run
    priv <- fmap SB.init $ SB.readFile $ path
    pub <- fmap SB.init $ SB.readFile $ path <.> "pub"
    return (priv, pub)
  where
    pass = case mbPass of
        Nothing -> ""
        Just p  -> SB.unpack p
    base = "crypto-pubkey-openssh-tests"
    typ = case t of
        OpenSshKeyTypeRsa -> "rsa"
        OpenSshKeyTypeDsa -> "dsa"

testWithOpenSsh :: OpenSshKeyType -> Maybe Passphrase -> Property
testWithOpenSsh t mbPass = monadicIO $ do
    (priv, pub) <- run $ openSshKeys t mbPass
    assert $ checkPublic (decodePublic pub) pub
    assert $ checkPrivate (decodePrivate priv mbPass) priv
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
                encodePrivate k mbPass == b
            _                                 -> False
        OpenSshKeyTypeDsa -> \r b -> case r of
            Right k@(OpenSshPrivateKeyDsa _) ->
                encodePrivate k mbPass == b
            _                                 -> False

main :: IO ()
main = defaultMain
    [
#ifdef OPENSSH
      testGroup "ssh-keygen" [ testProperty "decode/encode" $ testWithOpenSsh
                             ]
#endif
    ]
