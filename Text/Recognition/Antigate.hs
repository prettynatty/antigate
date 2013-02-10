{-# LANGUAGE
     DeriveFunctor
    ,PatternGuards
    ,BangPatterns
    ,OverloadedStrings
    ,DeriveDataTypeable
    ,FlexibleContexts
    ,RecordWildCards
    ,CPP
    #-}
-- | Example:
--
-- > {-# LANGUAGE OverloadedStrings #-}
-- > import Text.Recognition.Antigate
-- > import Data.Default
-- > import Network
-- > import Control.Monad
-- > import Control.Monad.IO.Class
-- > import Data.ByteString.Lazy hiding (putStrLn)
-- > import System.Timeout
-- > 
-- > myApiKey :: ApiKey
-- > myApiKey = "0123456789abcdef0123456789abcdef"
-- > 
-- > downloadJpegCaptcha :: Manager -> IO ByteString
-- > downloadJpegCaptcha = undefined
-- > 
-- > answerCaptcha :: String -> Manager -> IO Bool
-- > answerCaptcha = undefined
-- > 
-- > main :: IO ()
-- > main = withSocketsDo $ do
-- >     res <- timeout (30*1000000) $ withManager $ \m -> do
-- >         bytes <- liftIO $ downloadJpegCaptcha m
-- >         (id, answer) <- solveCaptcha def myApiKey def{phrase=True} "captcha.jpg" bytes m
-- >         res <- liftIO $ answerCaptcha answer m
-- >         unless res $ reportBad myApiKey id m
-- >         return res
-- >     case res of
-- >         Nothing -> do
-- >             putStrLn "Timed out"
-- >         Just True -> do
-- >             putStrLn "Solved successfully"
-- >         Just False -> do
-- >             putStrLn "Couldn't solve"

module Text.Recognition.Antigate
    (ApiKey(..)
    ,CaptchaID
    ,CaptchaConf(..)
    ,ApiResult(..)
    -- * High level
    ,SolveException(..)
    ,SolveConf(..)
    ,Phase(..)
    ,solveCaptcha
    ,solveCaptchaFromFile
    -- * Core functions
    ,uploadCaptcha
    ,uploadCaptchaFromFile
    ,checkCaptcha
    ,checkCaptchas
    ,reportBad
    ,getBalance
    -- * Connection manager
    ,Manager
    ,newManager
    ,closeManager
    ,withManager
    -- * Miscellaneous
    ,parseUploadResponse
    ,parseCheckResponse
    ,parseMultiCheckResponse
    ,parseMultiCheckResponses
    ,renderApiResult
    ) where
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import qualified Data.Text.Encoding.Error as TEE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Lazy.Char8()

import Network.HTTP.Conduit hiding (httpLbs)
import qualified Network.HTTP.Conduit
import Network.HTTP.Conduit.MultipartFormData

import Control.Concurrent (threadDelay)
import Control.Exception (Exception, throwIO)
import Data.Typeable (Typeable)

import Control.Monad.Trans.Resource
import Control.Monad.IO.Class (liftIO)
import Control.Applicative ((<$>), (<$))
import Data.Default (Default(..))
import Data.List (stripPrefix, isPrefixOf, isInfixOf, intercalate)
import Data.Maybe (catMaybes, fromMaybe)
import Data.String (IsString(..))
import Data.Word (Word)
import Safe (readMay)
import Text.Printf (printf)

decodeUtf8 :: BL.ByteString -> TL.Text
decodeUtf8 = TLE.decodeUtf8With TEE.lenientDecode

httpLbs :: Request (ResourceT IO) -> Manager -> ResourceT IO (Response BL.ByteString)
httpLbs r m = Network.HTTP.Conduit.httpLbs r{responseTimeout=Nothing} m

httpGet :: MonadResource m => Manager -> String -> m BL.ByteString
httpGet m u = liftResourceT $ do
    rq <- parseUrl u
    responseBody <$> httpLbs rq m

delimit :: Char -> String -> [String]
delimit _ [] = []
delimit a b =
    case break (==a) b of
        (c, []) -> [c]
        (c, (_:d)) -> c : delimit a d

-- | Antigate API access key paired with service provider's host.
-- At least these services claim to support Antigate API: 
-- Antigate, Captchabot, Decaptcher, ExpertDecoders, ImageTyperz,
-- DeathByCaptcha and Pixodrom.
data ApiKey = ApiKey
    {api_host :: String -- ^ default: \"antigate.com\"
    ,api_key :: String
    }
  deriving (Eq, Ord, Show, Read)

instance IsString ApiKey where
    fromString str = ApiKey
            {api_host = "antigate.com"
            ,api_key = str}

type CaptchaID = Int

-- | Properties of the captcha to be solved. See <http://antigate.com/panel.php?action=api>
data CaptchaConf = CaptchaConf
    {phrase :: Bool -- ^ * 'False' = default value (one word)
                    --
                    -- * 'True' = captcha has 2-4 words
    ,regsense :: Bool -- ^ * 'False' = default value (case is not important)
                      --
                      -- * 'True' = captcha is case sensitive
    ,numeric :: Maybe Bool -- ^ * 'Nothing' = default value
                           --
                           -- * 'Just' 'True' = captcha consists from numbers only
                           --
                           -- * 'Just' 'False' = captcha does not have numbers on it 
    ,calc :: Bool -- ^ * 'False' = default value
                  --
                  -- * 'True' = numbers on captcha must be summed
    ,min_len :: Word -- ^ * 0 = default value
                     --
                     -- * \>0 = minimum length of captcha text workers required to input 
    ,max_len :: Word -- ^ * 0 = default value (unlimited)
                     --
                     -- * \>0 = maximum length of captcha text workers required to input 
    ,is_russian :: Bool -- ^ * 'False' = default value
                        --
                        -- * 'True' = captcha goes to Russian-speaking worker 
    ,max_bid :: Maybe Double -- ^ 'Default' value is set on bids page. This parameter allows to control maximum bid without setting it on the bids page.
    }
    deriving (Show, Read)

data ApiResult a
    = OK a
    | CAPCHA_NOT_READY -- ^ captcha is not recognized yet, repeat request withing 1-5 seconds
    | ERROR_WRONG_USER_KEY -- ^ user authorization key is invalid (its length is not 32 bytes as it should be)
    | ERROR_WRONG_ID_FORMAT -- ^ the captcha ID you are sending is non-numeric
    | ERROR_KEY_DOES_NOT_EXIST -- ^ you have set wrong user authorization key in request
    | ERROR_ZERO_BALANCE -- ^ account has zero or negative balance
    | ERROR_NO_SLOT_AVAILABLE -- ^ no idle captcha workers are available at the moment, please try a bit later or try increasing your bid
    | ERROR_ZERO_CAPTCHA_FILESIZE -- ^ the size of the captcha you are uploading or pointing to is zero
    | ERROR_TOO_BIG_CAPTCHA_FILESIZE -- ^ your captcha size is exceeding 100kb limit
    | ERROR_WRONG_FILE_EXTENSION -- ^ your captcha file has wrong extension, the only allowed extensions are gif,jpg,jpeg,png
    | ERROR_IMAGE_TYPE_NOT_SUPPORTED -- ^ Could not determine captcha file type, only allowed formats are JPG, GIF, PNG
    | ERROR_IP_NOT_ALLOWED -- ^ Request with current account key is not allowed from your IP. Please refer to IP list section
    | ERROR_UNKNOWN String
  deriving (Show, Read, Eq, Functor)

instance Default CaptchaConf where
    def = CaptchaConf
        {phrase = False
        ,regsense = False
        ,numeric = Nothing
        ,calc = False
        ,min_len = 0
        ,max_len = 0
        ,is_russian = False
        ,max_bid = Nothing
        }

hostExt :: String -> String
hostExt host
    | "pixodrom.com" `isInfixOf` host = "aspx"
    | otherwise = "php"

captchaConfFields :: (Monad m, Monad m') => CaptchaConf -> [Part m m']
captchaConfFields c = catMaybes
        [bool "phrase" phrase
        ,bool "regsense" regsense
        ,tri "numeric" numeric
        ,bool "calc" calc
        ,num "min_len" min_len
        ,num "max_len" max_len
        ,bool "is_russian" is_russian
        ,partBS "max_bid" . fromString . printf "%f" <$> max_bid c
        ]
    where fromBool False = "0"
          fromBool True = "1"
          fromTri Nothing = "0"
          fromTri (Just True) = "1"
          fromTri (Just False) = "2"
          optField :: (Monad m, Monad m', Eq a) => T.Text -> (a -> BS.ByteString) -> CaptchaConf -> (CaptchaConf -> a) -> Maybe (Part m m')
          optField name conv conf get = do
            let rec = get conf
            if rec == get def
              then Nothing
              else Just $ partBS name $ conv rec
          bool name = optField name fromBool c
          tri name = optField name fromTri c
          num name = optField name (fromString . show) c

-- | report bad captcha result
--
-- throws 'HttpException' on network errors.
reportBad :: MonadResource m => ApiKey -> CaptchaID -> Manager -> m Bool
reportBad ApiKey{..} captchaid m = do
    lbs <- httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=reportbad&id=" ++ show captchaid
    return $ lbs == "OK_REPORT_RECORDED"

-- | retrieve your current account balance
--
-- throws 'HttpException' on network errors.
getBalance :: MonadResource m => ApiKey -> Manager -> m Double
getBalance ApiKey{..} m =
    fmap (read . TL.unpack . decodeUtf8) $ httpGet m $
        "http://"++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++"&action=getbalance"

uploadReq :: MonadResource m => Manager -> ApiKey -> CaptchaConf -> Part m (ResourceT IO) -> m (ApiResult CaptchaID)
uploadReq m ApiKey{..} conf part = do
    url <- liftIO $ parseUrl $ "http://" ++ api_host ++ "/in." ++ hostExt api_host
    req <- (`formDataBody` url) $
        ([partBS "method" "post"
         ,partBS "key" (fromString api_key)
        ]) ++
        (captchaConfFields conf
        ) ++
        [part]
    liftResourceT $ parseUploadResponse . TL.unpack . decodeUtf8 . responseBody <$> httpLbs req m

-- | upload captcha for recognition
--
-- throws 'HttpException' on network errors.
uploadCaptcha :: MonadResource m => ApiKey -> CaptchaConf -> FilePath -> BL.ByteString -> Manager -> m (ApiResult CaptchaID)
uploadCaptcha key sets filename image m = do
    uploadReq m key sets $ partFileRequestBody "file" filename $ RequestBodyLBS image

uploadCaptchaFromFile :: MonadResource m => ApiKey -> CaptchaConf -> FilePath -> Manager -> m (ApiResult CaptchaID)
uploadCaptchaFromFile key sets filename m = do
    uploadReq m key sets $ partFile "file" filename

-- | Marshal "ApiResult" back to its text form
renderApiResult :: ApiResult String -> String
renderApiResult (OK s) = "OK|" ++ s
renderApiResult (ERROR_UNKNOWN s) = s
renderApiResult a = show a

-- | Parse antigate's upload response
parseUploadResponse :: String -> ApiResult CaptchaID
parseUploadResponse s
    | Just e <- readMay s = e
    | otherwise =
        fromMaybe (ERROR_UNKNOWN s) $
            OK <$> (readMay =<< stripPrefix "OK|" s)

-- | Parse antigate's check response
parseCheckResponse :: String -> ApiResult String
parseCheckResponse s
    | Just e <- readMay s = e
    | otherwise =
        fromMaybe (ERROR_UNKNOWN s) $
            OK <$> stripPrefix "OK|" s

-- | Parse antigate's multi-check response
parseMultiCheckResponse :: String -> ApiResult String
parseMultiCheckResponse s
    | Just e <- readMay s = e
    | isPrefixOf "ERROR_" s = ERROR_UNKNOWN s
    | otherwise = OK s

-- | Parse antigate's multi-check response
parseMultiCheckResponses :: String -> [ApiResult String]
parseMultiCheckResponses = map parseMultiCheckResponse . delimit '|'

-- | retrieve captcha status
--
-- throws 'HttpException' on network errors.
checkCaptcha :: MonadResource m => ApiKey -> CaptchaID -> Manager -> m (ApiResult String)
checkCaptcha ApiKey{..} captchaid m =
    fmap (parseCheckResponse . TL.unpack . decodeUtf8) $ httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=get&id=" ++ show captchaid

-- | retrieve multiple captcha status
--
-- throws 'HttpException' on network errors.
checkCaptchas :: MonadResource m => ApiKey -> [CaptchaID] -> Manager -> m [ApiResult String]
checkCaptchas ApiKey{..} captchaids m =
    fmap (parseMultiCheckResponses . TL.unpack . decodeUtf8) $ httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=get&ids=" ++ intercalate "," (map show captchaids)

data SolveException
    = SolveExceptionUpload (ApiResult ())
    | SolveExceptionCheck CaptchaID (ApiResult ())
  deriving (Show, Typeable)

instance Exception SolveException

data Phase = UploadPhase | CheckPhase
  deriving (Show, Read, Eq, Ord, Enum, Bounded)

data SolveConf = SolveConf
    {
    -- | how much to sleep while waiting for available slot; in microseconds.
    --
    -- Default: @[3000000]@
     api_upload_sleep :: [Int]
    -- | how much to sleep between captcha checks; in microseconds.
    --
    -- Default: @[6000000,2000000,3000000] -- sleep 6 seconds before checking, on first retry sleep 2 seconds, then always sleep 3 seconds. List can be infinite@
    ,api_check_sleep :: [Int]
    -- | 'api_counter' will be called at the start of each phase
    --
    -- > api_counter = \phase count -> do
    -- >     if count == 0
    -- >       then putStrLn $ show phase ++ " began"
    -- >       else putStrLn $ show phase ++ " retries: " ++ show count
    --
    -- Default: @\_ _ -> return ()@
    ,api_counter :: Phase
                 -> Int
                 -> IO ()
    ,api_upload_callback :: CaptchaID -> IO () -- ^ This will be called when upload phase finishes
    }

instance Default SolveConf where
    def = SolveConf
        {api_upload_sleep = [3000000]
        ,api_check_sleep = [6000000,2000000,3000000]
        ,api_counter = const (const (return ()))
        ,api_upload_callback = const (return ())
        }

instance Show SolveConf where
    showsPrec d SolveConf{..} =
        showParen (d>=11) $ showString "SolveConf{api_upload_sleep = " .
            shows api_upload_sleep . showString ", api_check_sleep = " .
                shows api_check_sleep . showString
                    ", api_counter = <Phase -> Int -> IO ()>, api_upload_callback = <CaptchaID -> IO ()>}"

-- | High level function to solve captcha, blocks until answer is provided (about 2-10 seconds).
--
-- throws 'SolveException' or 'HttpException' when something goes wrong.
solveCaptcha :: MonadResource m
             => SolveConf
             -> ApiKey
             -> CaptchaConf
             -> FilePath -- ^ image filename (antigate guesses filetype by file extension)
             -> BL.ByteString -- ^ image contents
             -> Manager -- ^ HTTP connection manager to use
             -> m (CaptchaID, String)
solveCaptcha SolveConf{..} key conf filename image m = do
    liftIO $ api_counter UploadPhase 0
    captchaid <- goupload 1 api_upload_sleep
    liftIO $ api_upload_callback captchaid
    liftIO $ api_counter CheckPhase 0
    gocheck captchaid 1 api_check_sleep
  where
    goupload _ [] = error "solveCaptcha: api_upload_sleep is empty"
    goupload !c s_@(s:ss) = do
        ur <- uploadCaptcha key conf filename image m
        case ur of
            ERROR_NO_SLOT_AVAILABLE -> do
                liftIO $ api_counter UploadPhase c
                liftIO $ threadDelay s
                goupload (c+1) (if null ss then cycle s_ else ss)
            OK i -> return i
            a -> liftIO $ throwIO $ SolveExceptionUpload $ () <$ a
    gocheck _ _ [] = error "solveCaptcha: api_check_sleep is empty"
    gocheck captchaid !c s_@(s:ss) = do
        liftIO $ threadDelay s
        res <- checkCaptcha key captchaid m
        case res of
            CAPCHA_NOT_READY -> do
                liftIO $ api_counter CheckPhase c
                gocheck captchaid (c+1) (if null ss then cycle s_ else ss)
            OK answer ->
                return (captchaid, answer)
            ex -> liftIO $ throwIO $ SolveExceptionCheck captchaid $ () <$ ex

solveCaptchaFromFile :: (MonadBaseControl IO m, MonadResource m) => SolveConf -> ApiKey -> CaptchaConf -> FilePath -> Manager -> m (CaptchaID, String)
solveCaptchaFromFile a b c d m = do
    s <- liftIO (fromStrict' <$> BS.readFile d)
    solveCaptcha a b c d s m
  where
#if MIN_VERSION_bytestring(0,10,0)
    fromStrict' = fromStrict
#else
    fromStrict' x = BL.fromChunks [x]
#endif
