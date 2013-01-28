crypto-pubkey-openssh [![Build Status](https://secure.travis-ci.org/knsd/crypto-pubkey-openssh.png)](http://travis-ci.org/knsd/crypto-pubkey-openssh)
=====================

OpenSSH public keys parser, example.

```haskell
import System.Environment (getArgs)
import qualified Data.ByteString as B

import Crypto.PubKey.OpenSsh (decode)

main :: IO ()
main = do
    fname <- fmap head getArgs
    content <- B.readFile fname
    case decode content of
        Left e -> error e
        Right key -> print key
```
