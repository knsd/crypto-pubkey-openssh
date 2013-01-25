module Crypto.PubKey.OpenSsh
    ( OpenSshPublicKey(..)
    , openSshPublicKeyParser
    , parseOpenSshPublicKey
    ) where

import Crypto.PubKey.OpenSsh.Internal (OpenSshPublicKey(..),
                                       openSshPublicKeyParser,
                                       parseOpenSshPublicKey)