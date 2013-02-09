{-# LANGUAGE
     PatternGuards
    ,BangPatterns
    ,OverloadedStrings
    ,DeriveDataTypeable
    ,FlexibleContexts
    ,RecordWildCards
    #-}
-- | Example:
--
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
    ,UploadResult(..)
    ,CheckResult(..)
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
    ,parseUploadResult
    ,parseCheckResult
    ,parseCheckResults
    ,parseCheckResultNoOK
    ,renderUploadResult
    ,renderCheckResult
    ) where
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import qualified Data.Text.Encoding.Error as TEE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

import Network.HTTP.Conduit hiding (httpLbs)
import qualified Network.HTTP.Conduit
import Network.HTTP.Conduit.MultipartFormData

import Control.Concurrent (threadDelay)
import Control.Exception (Exception, throwIO)
import Data.Typeable (Typeable)

import Control.Monad.Trans.Resource
import Control.Monad.IO.Class (liftIO)
import Control.Monad (void)
import Control.Applicative ((<$>))
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

data UploadResult = UPLOAD_OK CaptchaID -- ^ result is positive, your captcha is accepted for recognition and its ID follows. You may now attempt to retrieve captcha status with this ID.
                  | ERROR_WRONG_USER_KEY -- ^ user authorization key is invalid (its length is not 32 bytes as it should be)
                  | UPLOAD_ERROR_KEY_DOES_NOT_EXIST -- ^ you have set wrong user authorization key in request
                  | ERROR_ZERO_BALANCE -- ^ account has zero or negative balance
                  | ERROR_NO_SLOT_AVAILABLE -- ^ no idle captcha workers are available at the moment, please try a bit later or try increasing your bid
                  | ERROR_ZERO_CAPTCHA_FILESIZE -- ^ the size of the captcha you are uploading or pointing to is zero
                  | ERROR_TOO_BIG_CAPTCHA_FILESIZE -- ^ your captcha size is exceeding 100kb limit
                  | ERROR_WRONG_FILE_EXTENSION -- ^ your captcha file has wrong extension, the only allowed extensions are gif,jpg,jpeg,png
                  | ERROR_IMAGE_TYPE_NOT_SUPPORTED -- ^ Could not determine captcha file type, only allowed formats are JPG, GIF, PNG
                  | ERROR_IP_NOT_ALLOWED -- ^ Request with current account key is not allowed from your IP. Please refer to IP list section
                  | UPLOAD_ERROR_UNKNOWN String
    deriving (Show, Read, Eq, Ord)

data CheckResult = CHECK_OK String -- ^ the captcha is recognized, the guessed text follows
                 | CAPCHA_NOT_READY -- ^ captcha is not recognized yet, repeat request withing 1-5 seconds
                 | CHECK_ERROR_KEY_DOES_NOT_EXIST -- ^ you have set wrong user authorization key in request
                 | ERROR_WRONG_ID_FORMAT -- ^ the captcha ID you are sending is non-numeric
                 | CHECK_ERROR_UNKNOWN String
    deriving (Show, Read, Eq, Ord)

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
reportBad :: MonadResource m => ApiKey -> CaptchaID -> Manager -> m ()
reportBad ApiKey{..} captchaid m =
    void $ httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=reportbad&id=" ++ show captchaid

-- | retrieve your current account balance
--
-- throws 'HttpException' on network errors.
getBalance :: MonadResource m => ApiKey -> Manager -> m Double
getBalance ApiKey{..} m =
    fmap (read . TL.unpack . decodeUtf8) $ httpGet m $
        "http://"++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++"&action=getbalance"

-- | Marshal "UploadResult" back to its text form
renderUploadResult :: UploadResult -> String
renderUploadResult (UPLOAD_OK i) = "OK|" ++ show i
renderUploadResult (UPLOAD_ERROR_UNKNOWN s) = s
renderUploadResult a = show a

-- | Parse antigate's upload response
parseUploadResult :: String -> UploadResult
parseUploadResult "ERROR_KEY_DOES_NOT_EXIST" = UPLOAD_ERROR_KEY_DOES_NOT_EXIST
parseUploadResult s
    | Just e <- readMay s = e
    | otherwise =
        fromMaybe (UPLOAD_ERROR_UNKNOWN s) $
            UPLOAD_OK <$> (readMay =<< stripPrefix "OK|" s)

inReq :: MonadResource m => Manager -> ApiKey -> CaptchaConf -> Part m (ResourceT IO) -> m UploadResult
inReq m ApiKey{..} conf part = do
    url <- liftIO $ parseUrl $ "http://" ++ api_host ++ "/in." ++ hostExt api_host
    req <- (`formDataBody` url) $
        ([partBS "method" "post"
         ,partBS "key" (fromString api_key)
        ]) ++
        (captchaConfFields conf
        ) ++
        [part]
    liftResourceT $ parseUploadResult . TL.unpack . decodeUtf8 . responseBody <$> httpLbs req m

-- | upload captcha for recognition
--
-- throws 'HttpException' on network errors.
uploadCaptcha :: MonadResource m => ApiKey -> CaptchaConf -> FilePath -> BL.ByteString -> Manager -> m UploadResult
uploadCaptcha key sets filename image m = do
    inReq m key sets $ partFileRequestBody "file" filename $ RequestBodyLBS image

uploadCaptchaFromFile :: MonadResource m => ApiKey -> CaptchaConf -> FilePath -> Manager -> m UploadResult
uploadCaptchaFromFile key sets filename m = do
    inReq m key sets $ partFile "file" filename

-- | Marshal "CheckResult" back to its text form 
renderCheckResult :: CheckResult -> String
renderCheckResult (CHECK_OK s) = "OK|" ++ s
renderCheckResult (CHECK_ERROR_UNKNOWN s) = s
renderCheckResult a = show a

-- | Parse antigate's check response
parseCheckResult :: String -> CheckResult
parseCheckResult "ERROR_KEY_DOES_NOT_EXIST" = CHECK_ERROR_KEY_DOES_NOT_EXIST
parseCheckResult s
    | Just e <- readMay s = e
    | otherwise = fromMaybe (CHECK_ERROR_UNKNOWN s) $
                        CHECK_OK <$> stripPrefix "OK|" s

-- | Parse antigate's multi-check response
parseCheckResultNoOK :: String -> CheckResult
parseCheckResultNoOK "ERROR_KEY_DOES_NOT_EXIST" = CHECK_ERROR_KEY_DOES_NOT_EXIST
parseCheckResultNoOK s
    | Just e <- readMay s = e
    | isPrefixOf "ERROR_" s = CHECK_ERROR_UNKNOWN s
    | otherwise = CHECK_OK s

-- | Parse antigate's multi-check response
parseCheckResults :: String -> [CheckResult]
parseCheckResults = map parseCheckResultNoOK . delimit '|'

-- | retrieve captcha status
--
-- throws 'HttpException' on network errors.
checkCaptcha :: MonadResource m => ApiKey -> CaptchaID -> Manager -> m CheckResult
checkCaptcha ApiKey{..} captchaid m =
    fmap (parseCheckResult . TL.unpack . decodeUtf8) $ httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=get&id=" ++ show captchaid

-- | retrieve multiple captcha status
--
-- throws 'HttpException' on network errors.
checkCaptchas :: MonadResource m => ApiKey -> [CaptchaID] -> Manager -> m [CheckResult]
checkCaptchas ApiKey{..} captchaids m =
    fmap (parseCheckResults . TL.unpack . decodeUtf8) $ httpGet m $
        "http://" ++ api_host ++ "/res." ++ hostExt api_host ++ "?key=" ++
            api_key ++ "&action=get&ids=" ++ intercalate "," (map show captchaids)

data SolveException = SolveExceptionUpload UploadResult
                    | SolveExceptionCheck CaptchaID CheckResult
  deriving (Show, Typeable)

instance Exception SolveException

data Phase = UploadPhase | CheckPhase
  deriving (Show, Read, Eq, Ord, Enum, Bounded)

data SolveConf = SolveConf
    {api_upload_sleep :: Int -- ^ how much to sleep while waiting for available slot. Microseconds.
    ,api_check_sleep :: Int -- ^ how much to sleep between captcha checks. Microseconds.
    ,api_counter :: Phase -- ^ Current solving phase
                 -> Int   -- ^ Number of times counter was called during this phase, starting at @0@
                 -> IO () -- ^ This action will be executed before each sleep. e.g. 'System.IO.print'
    }

instance Default SolveConf where
    def = SolveConf
        {api_upload_sleep = 3000000
        ,api_check_sleep = 3000000
        ,api_counter = const (const (return ()))
        }

instance Show SolveConf where
    showsPrec d SolveConf{..} =
        showParen (d>=11) $ showString "SolveConf{api_upload_sleep = " .
            shows api_upload_sleep . showString ", api_check_sleep = " .
                shows api_check_sleep . showString ", api_counter = <Phase -> IO ()>}"

-- | High level function to solve captcha, blocks until answer is provided (about 2-10 seconds).
--
-- throws 'SolveException' or 'HttpException' when something goes wrong.
solveCaptcha :: MonadResource m =>
                SolveConf
             -> ApiKey
             -> CaptchaConf
             -> FilePath -- ^ image filename (antigate guesses filetype by file extension)
             -> BL.ByteString -- ^ image contents
             -> Manager -- ^ HTTP connection manager to use
             -> m (CaptchaID, String)
solveCaptcha SolveConf{..} key conf filename image m = goupload 0
  where
    goupload !c = do
        ur <- uploadCaptcha key conf filename image m
        case ur of
            ERROR_NO_SLOT_AVAILABLE -> do
                liftIO $ api_counter UploadPhase c
                liftIO $ threadDelay api_upload_sleep
                goupload (c+1)
            UPLOAD_OK i -> gocheck i 0
            a -> liftIO $ throwIO $ SolveExceptionUpload a
    gocheck captchaid !c = do
        liftIO $ threadDelay api_check_sleep
        res <- checkCaptcha key captchaid m
        case res of
            CHECK_OK answer ->
                return (captchaid, answer)
            CAPCHA_NOT_READY -> do
                liftIO $ api_counter CheckPhase c
                gocheck captchaid (c+1)
            ex -> liftIO $ throwIO $ SolveExceptionCheck captchaid ex

solveCaptchaFromFile :: (MonadBaseControl IO m, MonadResource m) => SolveConf -> ApiKey -> CaptchaConf -> FilePath -> Manager -> m (CaptchaID, String)
solveCaptchaFromFile a b c d m =
    liftIO (BL.readFile d) >>= \s -> solveCaptcha a b c d s m
