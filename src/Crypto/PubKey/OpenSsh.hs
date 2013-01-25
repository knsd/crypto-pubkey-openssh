{-# LANGUAGE OverloadedStrings #-}

module Crypto.PubKey.OpenSsh
    ( OpenSshPublicKey(..)
    , openSshPublicKeyParser
    , parseOpenSshPublicKey
    , serializeOpenSshPublicKey
    ) where

import Prelude hiding (take)

import Control.Applicative ((*>), (<|>))
import Control.Monad (void, replicateM, when)
import Data.ByteString.Char8 (ByteString)
import Data.Bits (testBit)
import Data.Char (isControl)
import Data.List (unfoldr)
import Data.Word (Word8)

import Data.Attoparsec.ByteString.Char8 (Parser, parseOnly, take, space,
                                         isSpace, takeTill)
import Data.Serialize (Get, getBytes, runGet, getWord32be, getWord8,
                       Put, Putter, runPut, putByteString)
import qualified Data.ByteString.Base64 as Base64
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

-- NOTE(rocco66): hope Integer is always positive
fixZeroByte :: [Word8] -> [Word8]
fixZeroByte bs = if testBit (head bs) msb then 0:bs else bs
  where
    msb = 7

expandInteger :: Integer -> [Word8]
expandInteger n = reverse $ unfoldr expand $ abs n
  where
    expand :: Integer -> Maybe (Word8, Integer)
    expand e | e == 0    = Nothing
             | otherwise = Just $ getResults $ quotRem e 256
    getResults :: (Integer, Integer) -> (Word8, Integer)
    getResults (i, w) = (fromIntegral w, i)

fillSize :: [Word8] -> [Word8]
fillSize l = replicate (4 - length l) (0 :: Word8) ++ l

class IntegerSerial a where
    intserRepr :: a -> [Word8]
    intserW8 :: a -> [Word8]
    intserW8 a = fillSize (intserSize a) ++ intserRepr a
    intserSize :: a -> [Word8]
    intserSize = expandInteger . toInteger . length . intserRepr

instance IntegerSerial ByteString where
    intserRepr = BS.unpack

instance IntegerSerial Integer where
    intserRepr = fixZeroByte . expandInteger

commonPublicKeyPutter :: ByteString
                      -> ByteString
                      -> [Word8]
                      -> Put
commonPublicKeyPutter keyType comment body = do
    putByteString keyType
    putByteString " "
    putByteString $ Base64.encode $ BS.pack body
    when (not $ BS.null comment) $ do
        putByteString " "
        putByteString comment

openSshPublicKeyPutter :: Putter OpenSshPublicKey
openSshPublicKeyPutter (OpenSshPublicKeyRsa
                        (RSA.PublicKey _ public_n public_e)
                        comment) =
    commonPublicKeyPutter "ssh-rsa" comment $ concat
        [ intserW8 ("ssh-rsa" :: ByteString)
        , intserW8 public_e
        , intserW8 public_n ]

openSshPublicKeyPutter (OpenSshPublicKeyDsa
                        (DSA.PublicKey (public_p, public_g, public_q) public_y)
                        comment) =
    commonPublicKeyPutter "ssh-dss" comment $ concat
        [ intserW8 ("ssh-dss" :: ByteString)
        , intserW8 public_p
        , intserW8 public_q
        , intserW8 public_g
        , intserW8 public_y ]

serializeOpenSshPublicKey :: OpenSshPublicKey -> ByteString
serializeOpenSshPublicKey = runPut . openSshPublicKeyPutter