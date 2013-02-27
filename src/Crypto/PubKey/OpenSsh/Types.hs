module Crypto.PubKey.OpenSsh.Types where

import Data.ByteString (ByteString)

import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.Types.PubKey.RSA as RSA

data OpenSshPrivateKey = OpenSshPrivateKeyRsa RSA.PrivateKey
                       | OpenSshPrivateKeyDsa DSA.PrivateKey
    deriving (Eq, Show)

data OpenSshPublicKey = OpenSshPublicKeyRsa RSA.PublicKey ByteString
                      | OpenSshPublicKeyDsa DSA.PublicKey ByteString
    deriving (Eq, Show)

data OpenSshKeyType = OpenSshKeyTypeRsa
                    | OpenSshKeyTypeDsa
    deriving (Eq, Show)

type Passphrase = ByteString
