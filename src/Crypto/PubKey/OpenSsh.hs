{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.PubKey.OpenSsh
    ( OpenSshPublicKey(..)
    , IntegerSerial(..)
    , openSshPublicKeyParser
    , parseOpenSshPublicKey
    , serializeOpenSshPublicKey
    , expandInteger
    ) where

import Prelude hiding (take)

import Control.Applicative ((*>), (<|>))
import Control.Monad (void, replicateM)
import Data.ByteString.Char8 (ByteString)
import Data.Char (isControl)
import Data.List (unfoldr)
import Data.Word (Word8, Word32)

import Data.Attoparsec.ByteString.Char8 (Parser, parseOnly, take, space,
                                         isSpace, takeTill)
import Data.Serialize (Get, getBytes, runGet, getWord32be, getWord8,
                       Putter, runPut, putWord32be, putWord8, putByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString as BS
import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.Types.PubKey.RSA as RSA

data OpenSshPublicKey = OpenSshPublicKeyRsa RSA.PublicKey ByteString
                      | OpenSshPublicKeyDsa DSA.PublicKey ByteString
    deriving (Eq, Show)

data OpenSshPublicKeyType = OpenSshPublicKeyTypeRsa
                          | OpenSshPublicKeyTypeDsa
    deriving (Eq, Show)

typeSize :: Int
typeSize = 7

readType :: Monad m => ByteString -> m OpenSshPublicKeyType
readType "ssh-rsa" = return OpenSshPublicKeyTypeRsa
readType "ssh-dss" = return OpenSshPublicKeyTypeDsa
readType _ = fail "Invalid key type"

calculateSize :: Integer -> Int
calculateSize = go 1
  where
    go i n | 2 ^ (i * 8) > n = i
           | otherwise       = go (i + 1) n

getInteger :: Get Integer
getInteger = do
    size <- fmap fromIntegral getWord32be
    ints <- fmap reverse $ replicateM size $ fmap toInteger getWord8
    return $ fst $ flip foldl1 (zip ints ([0..] :: [Integer])) $
        \(a, _) (c, p) -> (c * (256 ^ p) + a, p)

getOpenSshPublicKey :: Get (ByteString -> OpenSshPublicKey)
getOpenSshPublicKey = do
    size <- fmap fromIntegral $ getWord32be
    getBytes size >>= readType >>= \typ -> case typ of
        OpenSshPublicKeyTypeRsa -> parseRsa
        OpenSshPublicKeyTypeDsa -> parseDsa
  where
    parseRsa = do
        e <- getInteger
        n <- getInteger
        return $ OpenSshPublicKeyRsa $ RSA.PublicKey (calculateSize n) n e
    parseDsa = do
        p <- getInteger
        q <- getInteger
        g <- getInteger
        y <- getInteger
        return $ OpenSshPublicKeyDsa $ DSA.PublicKey (p, g, q) y

openSshPublicKeyParser :: Parser OpenSshPublicKey
openSshPublicKeyParser = do
    void $ readType =<< take typeSize
    void space
    b64 <- takeTill isSpace
    binary <- either fail return $ Base64.decode b64
    partialKey <- either fail return $ runGet getOpenSshPublicKey binary
    fmap partialKey commentParser
  where
    commentParser = void space *> (takeTill $ \c -> isSpace c || isControl c)
                <|> return ""

parseOpenSshPublicKey :: ByteString -> Either String OpenSshPublicKey
parseOpenSshPublicKey = parseOnly openSshPublicKeyParser

expandInteger :: Integer -> [Word8]
expandInteger = reverse . unfoldr expand
  where
    expand :: Integer -> Maybe (Word8, Integer)
    expand i | i == 0    = Nothing
             | otherwise = Just $ uncurry getResults $ quotRem i 256
    getResults :: Integer -> Integer -> (Word8, Integer)
    getResults i w = (fromIntegral w, i)

fillSize :: [Word8] -> [Word8]
fillSize l = replicate (4 - length l) (0 :: Word8) ++ l

class IntegerSerial a where
    intserSize :: a -> [Word8]
    intserRepr :: a -> [Word8]
    intserToBS :: a -> [Word8]
    intserToBS a = fillSize (intserSize a) ++
                   intserRepr a

instance IntegerSerial ByteString where
    intserSize = expandInteger . toInteger . length . BS.unpack
    intserRepr = BS.unpack

openSshPublicKeyPutter :: Putter OpenSshPublicKey
openSshPublicKeyPutter (OpenSshPublicKeyRsa
                        RSA.PublicKey { .. }
                        comment) = do
    putByteString "ssh-rsa"
    putByteString " "
    putByteString $ Base64.encode $ BS.pack $ intserToBS ("ssh-rsa" :: ByteString)
    putByteString " "
    putByteString comment
openSshPublicKeyPutter (OpenSshPublicKeyDsa
                        DSA.PublicKey { .. }
                        comment) = do
    putByteString "ssh-dss"
    putByteString " "
    putByteString " "
    putByteString comment

serializeOpenSshPublicKey :: OpenSshPublicKey -> ByteString
serializeOpenSshPublicKey = runPut . openSshPublicKeyPutter