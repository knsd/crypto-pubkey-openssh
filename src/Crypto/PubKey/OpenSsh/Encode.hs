{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

module Crypto.PubKey.OpenSsh.Encode where

import Control.Monad (when)
import Data.ByteString.Char8 (ByteString)
import Data.Bits (testBit)
import Data.List (unfoldr)
import Data.Word (Word8)
import qualified Data.ByteString as BS

import Data.Serialize (Put, Putter, runPut, putByteString, putWord32be, put)
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types (ASN1(IntVal, Start, End), ASN1ConstructionType(Sequence))
import Data.ASN1.BinaryEncoding (DER(..))
import Data.PEM (PEM(..), pemWriteBS)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ByteString.Base64 as Base64

import Crypto.PubKey.OpenSsh.Types (OpenSshKeyType(..), OpenSshPublicKey(..),
                                    OpenSshPrivateKey(..))

fixZeroByte :: [Word8] -> [Word8]
fixZeroByte [] = []
fixZeroByte bs = if testBit (head bs) msb then 0:bs else bs
  where
    msb = 7

expandInteger :: Integer -> [Word8]
expandInteger n = reverse $ unfoldr expand n
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
    putByteString $ pemWriteBS $ PEM "RSA PRIVATE KEY" [] body
commonPrivateKeyPutter OpenSshKeyTypeDsa body = do
    putByteString $ pemWriteBS $ PEM "DSA PRIVATE KEY" [] body

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

openSshPrivateKeyPutter :: Putter OpenSshPrivateKey
openSshPrivateKeyPutter (OpenSshPrivateKeyRsa (RSA.PrivateKey {..})) =
    let RSA.PublicKey{..} = private_pub
    in commonPrivateKeyPutter OpenSshKeyTypeRsa $ encodeASN1' DER
        [ Start Sequence
        , IntVal 0  -- version
        , IntVal public_n
        , IntVal public_e
        , IntVal private_d
        , IntVal private_p
        , IntVal private_q
        , IntVal private_dP
        , IntVal private_dQ
        , IntVal private_qinv
        , End Sequence
        ]
openSshPrivateKeyPutter (OpenSshPrivateKeyDsa (DSA.PrivateKey {..}) public_y) =
    let DSA.Params{..} = private_params
    in commonPrivateKeyPutter OpenSshKeyTypeDsa $ encodeASN1' DER
        [ Start Sequence
        , IntVal 0  -- version
        , IntVal params_p
        , IntVal params_q
        , IntVal params_g
        , IntVal public_y
        , IntVal private_x
        , End Sequence
        ]

encodePublic :: OpenSshPublicKey -> ByteString
encodePublic = runPut . openSshPublicKeyPutter

encodePrivate :: OpenSshPrivateKey -> ByteString
encodePrivate k = runPut $ openSshPrivateKeyPutter k
