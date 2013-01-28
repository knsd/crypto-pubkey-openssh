module Crypto.PubKey.OpenSsh
    ( OpenSshPublicKey(..)
    , encode
    , decode
    ) where

import Crypto.PubKey.OpenSsh.Types (OpenSshPublicKey(..))
import Crypto.PubKey.OpenSsh.Encode (encode)
import Crypto.PubKey.OpenSsh.Decode (decode)
