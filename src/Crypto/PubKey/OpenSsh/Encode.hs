{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

module Crypto.PubKey.OpenSsh.Encode where

import Control.Monad (when)
import Data.ByteString.Char8 (ByteString)
import Data.Bits (testBit)
import Data.List (unfoldr)
import Data.Word (Word8)
import qualified Data.ByteString as BS

import Data.Serialize (Put, Putter, runPut, putByteString, putWord32be, put)
import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Data.ByteString.Base64 as Base64

import Crypto.PubKey.OpenSsh.Types (OpenSshKeyType(..), Passphrase,
                                    OpenSshPublicKey(..), OpenSshPrivateKey(..))

fixZeroByte :: [Word8] -> [Word8]
fixZeroByte bs = if testBit (head bs) msb then 0:bs else bs
  where
    msb = 7

expandInteger :: Integer -> [Word8]
expandInteger n = reverse $ unfoldr expand $ n
  where
    expand :: Integer -> Maybe (Word8, Integer)
    expand e | e == 0    = Nothing
             | otherwise = Just $ getResults $ quotRem e 256
    getResults :: (Integer, Integer) -> (Word8, Integer)
    getResults (i, w) = (fromIntegral w, i)

keyTypePutter :: Putter OpenSshKeyType
keyTypePutter OpenSshKeyTypeRsa = putByteString "ssh-rsa"
keyTypePutter OpenSshKeyTypeDsa = putByteString "ssh-dss"

mpint :: Integer -> ByteString
mpint i = runPut $ do
    putWord32be $ fromIntegral $ length binary
    mapM_ put binary
  where
    binary = fixZeroByte $ expandInteger i

commonPublicKeyPutter :: OpenSshKeyType
                      -> ByteString
                      -> ByteString
                      -> Put
commonPublicKeyPutter keyType comment body = do
    keyTypePutter keyType
    putByteString " "
    putByteString $ Base64.encode $ BS.append wrapType body
    when (not $ BS.null comment) $ do
        putByteString " "
        putByteString comment
  where
    binaryType = runPut $ keyTypePutter keyType
    wrapType = runPut $ do
        putWord32be $ fromIntegral $ BS.length $ binaryType
        putByteString binaryType

commonPrivateKeyPutter :: OpenSshKeyType
                       -> ByteString
                       -> Put
commonPrivateKeyPutter OpenSshKeyTypeRsa body = do
    putByteString "-----BEGIN RSA PRIVATE KEY-----\n"
    putByteString body
    putByteString "-----END RSA PRIVATE KEY-----"
commonPrivateKeyPutter OpenSshKeyTypeDsa body = do
    putByteString "-----BEGIN DSA PRIVATE KEY-----\n"
    putByteString body
    putByteString "-----END DSA PRIVATE KEY-----"

openSshPublicKeyPutter :: Putter OpenSshPublicKey
openSshPublicKeyPutter (OpenSshPublicKeyRsa
                        (RSA.PublicKey _ public_n public_e)
                        comment) =
    commonPublicKeyPutter OpenSshKeyTypeRsa comment $ BS.concat
        [ mpint public_e
        , mpint public_n ]

openSshPublicKeyPutter (OpenSshPublicKeyDsa
                        (DSA.PublicKey (DSA.Params public_p public_g public_q) public_y)
                        comment) =
    commonPublicKeyPutter OpenSshKeyTypeDsa comment $ BS.concat
        [ mpint public_p
        , mpint public_q
        , mpint public_g
        , mpint public_y ]

openSshPrivateKeyPutter :: Maybe Passphrase -> Putter OpenSshPrivateKey
openSshPrivateKeyPutter (Just _)  _ = error "Passpharse not implemented"
openSshPrivateKeyPutter _ (OpenSshPrivateKeyRsa (RSA.PrivateKey {..})) =
    let RSA.PublicKey{..} = private_pub
    in commonPrivateKeyPutter OpenSshKeyTypeRsa $ BS.concat
        [ mpint 0 -- version
        , mpint public_n
        , mpint public_e
        , mpint private_d
        , mpint private_p
        , mpint private_q
        , mpint private_dP
        , mpint private_dQ
        , mpint private_qinv
        ]
openSshPrivateKeyPutter _ (OpenSshPrivateKeyDsa
                            (DSA.PrivateKey {..}) public_y) =
    let DSA.Params{..} = private_params
    in commonPrivateKeyPutter OpenSshKeyTypeDsa $ BS.concat
        [ mpint 0
        , mpint params_p
        , mpint params_q
        , mpint params_g
        , mpint public_y
        , mpint private_x
        ]

encodePublic :: OpenSshPublicKey -> ByteString
encodePublic = runPut . openSshPublicKeyPutter

encodePrivate :: OpenSshPrivateKey -> Maybe Passphrase -> ByteString
encodePrivate k p = runPut $ openSshPrivateKeyPutter p k
