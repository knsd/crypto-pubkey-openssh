{- OPTIONS_GHC -funbox-strict-fields -}

module Crypto.PubKey.OpenSsh.Types where

import Data.ByteString (ByteString)

import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA as RSA

data OpenSshPrivateKey = OpenSshPrivateKeyRsa !RSA.PrivateKey
                       | OpenSshPrivateKeyDsa !DSA.PrivateKey !DSA.PublicNumber
    deriving (Eq, Show)

-- | Public key contains `RSA` or `DSA` key and OpenSSH key description
data OpenSshPublicKey = OpenSshPublicKeyRsa !RSA.PublicKey !ByteString
                      | OpenSshPublicKeyDsa !DSA.PublicKey !ByteString
    deriving (Eq, Show)

data OpenSshKeyType = OpenSshKeyTypeRsa
                    | OpenSshKeyTypeDsa
    deriving (Eq, Show)
