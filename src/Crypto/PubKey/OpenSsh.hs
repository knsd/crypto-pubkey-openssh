{-# LANGUAGE OverloadedStrings #-}

module Crypto.PubKey.OpenSsh
    ( OpenSshPublicKey(..)
    , openSshPublicKeyParser
    , parseOpenSshPublicKey
    ) where

import Prelude hiding (take)

import Control.Monad (void, replicateM)
import Data.ByteString.Char8 (ByteString)

import Data.Attoparsec.ByteString.Char8 (Parser, parseOnly, take, space,
                                         isSpace, takeTill, atEnd)
import Data.Serialize (Get, getBytes, runGet, getWord32be, getWord8)
import qualified Data.ByteString.Base64 as Base64
import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.Types.PubKey.RSA as RSA


data OpenSshPublicKeyBody = OpenSshPublicKeyBodyRsa RSA.PublicKey
                          | OpenSshPublicKeyBodyDsa DSA.PublicKey
    deriving (Eq, Show)

type OpenSshTextTail = ByteString

data OpenSshPublicKey = OpenSshPublicKeyRsa RSA.PublicKey (Maybe OpenSshTextTail)
                      | OpenSshPublicKeyDsa DSA.PublicKey (Maybe OpenSshTextTail)
    deriving (Eq, Show)

makeFromBody :: OpenSshPublicKeyBody
             -> (Maybe OpenSshTextTail)
             -> OpenSshPublicKey
makeFromBody (OpenSshPublicKeyBodyRsa rsaPubKey) = OpenSshPublicKeyRsa rsaPubKey
makeFromBody (OpenSshPublicKeyBodyDsa dsaPubKey) = OpenSshPublicKeyDsa dsaPubKey

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

getOpenSshPublicKey :: Get OpenSshPublicKeyBody
getOpenSshPublicKey = do
    size <- fmap fromIntegral $ getWord32be
    getBytes size >>= readType >>= \typ -> case typ of
        OpenSshPublicKeyTypeRsa -> parseRsa
        OpenSshPublicKeyTypeDsa -> parseDsa
  where
    parseRsa = do
        e <- getInteger
        n <- getInteger
        return $ OpenSshPublicKeyBodyRsa $ RSA.PublicKey (calculateSize n) n e
    parseDsa = do
        p <- getInteger
        q <- getInteger
        g <- getInteger
        y <- getInteger
        return $ OpenSshPublicKeyBodyDsa $ DSA.PublicKey (p, g, q) y

openSshPublicKeyParser :: Parser OpenSshPublicKey
openSshPublicKeyParser = do
    _typ <- readType =<< take typeSize
    void space
    b64 <- takeTill isSpace
    binary <- eitherFail $ Base64.decode b64
    body <- eitherFail $ runGet getOpenSshPublicKey binary
    openSshKeyTail <- atEnd >>= \end -> if end
        then return Nothing
        else space >> takeTill isSpace >>= return . Just
    return $ makeFromBody body openSshKeyTail
  where
    eitherFail = either fail return

parseOpenSshPublicKey :: ByteString -> Either String OpenSshPublicKey
parseOpenSshPublicKey = parseOnly openSshPublicKeyParser
