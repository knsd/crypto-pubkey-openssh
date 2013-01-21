crypto-pubkey-openssh
=====================

OpenSSH public keys parser, example.

```haskell
import System.Environment (getArgs)
import qualified Data.ByteString as B

import Crypto.PubKey.OpenSsh (parseOpenSshPublicKey)

main :: IO ()
main = do
    fname <- fmap head getArgs
    content <- B.readFile fname
    case parseOpenSshPublicKey content of
        Left e -> error e
        Right key -> print key
```
