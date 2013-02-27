{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Crypto.PubKey.OpenSsh.Decode where

import Prelude hiding (take)

import Control.Applicative ((*>), (<|>))
import Control.Monad (void, replicateM)
import Data.ByteString.Char8 (ByteString)
import Data.Char (isControl)

import Data.Attoparsec.ByteString.Char8 (Parser, parseOnly, take, space,
                                     isSpace, takeTill)
import Data.PEM (PEM(..), pemParseBS)
import Data.Serialize (Get, getBytes, runGet, getWord32be, getWord8)
import qualified Data.ByteString.Base64 as Base64
import qualified Crypto.Types.PubKey.DSA as DSA
import qualified Crypto.Types.PubKey.RSA as RSA

import Crypto.PubKey.OpenSsh.Types (OpenSshKeyType(..),
                                    OpenSshPublicKey(..), OpenSshPrivateKey(..))

typeSize :: Int
typeSize = 7

readType :: Monad m => ByteString -> m OpenSshKeyType
readType "ssh-rsa" = return OpenSshKeyTypeRsa
readType "ssh-dss" = return OpenSshKeyTypeDsa
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
        OpenSshKeyTypeRsa -> parseRsa
        OpenSshKeyTypeDsa -> parseDsa
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

decodePublic :: ByteString -> Either String OpenSshPublicKey
decodePublic = parseOnly openSshPublicKeyParser

decodePrivate :: ByteString -> Either String OpenSshPrivateKey
decodePrivate bs = pemParseBS bs >>= \pems -> case pems of
    [] -> Left "Private key not found"
    (_:_:_) -> Left "Too many private keys"
    [PEM { .. }] -> do
        keyType <- case pemName of
                "RSA PRIVATE KEY" -> Right OpenSshKeyTypeRsa
                "DSA PRIVATE KEY" -> Right OpenSshKeyTypeDsa
                _                 -> Left "Unknown private key type"
        error "Not implemented"
