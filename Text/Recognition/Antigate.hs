{-# LANGUAGE PatternGuards, OverloadedStrings, ScopedTypeVariables, DeriveDataTypeable #-}
module Text.Recognition.Antigate
    (AntigateKey
    ,CaptchaID
    ,CaptchaConf(..)
    ,UploadResult(..)
    ,CheckResult(..)
    -- * High level
    ,SolveException(..)
    ,solveCaptcha
    ,solveCaptchaFromFile
    -- * Core functions
    ,uploadCaptcha
    ,checkCaptcha
    ,checkCaptchas
    ,reportBad
    ,getBalance
    -- * Miscellaneous
    ,parseUploadResult
    ,parseCheckResult
    ,parseCheckResults
    ,parseCheckResultNoOK
    ,renderUploadResult
    ,renderCheckResult
    ) where
import Control.Arrow (first)
import Control.Monad (void)
import Control.Applicative ((<$>))
import Control.Concurrent (threadDelay)
import Control.Exception (Exception, throwIO)
import qualified Codec.Binary.UTF8.Generic as UTF8 (fromString, toString)
import qualified Data.ByteString as S (concat)
import Data.ByteString.Lazy.Char8()
import Data.Default (Default(..))
import Data.List (stripPrefix, isPrefixOf, intercalate)
import Data.Monoid ((<>))
import Data.Maybe (catMaybes, fromMaybe, fromJust)
import Data.String (fromString)
import Data.Typeable (Typeable)
import Data.Word (Word)
import Network.Mime (defaultMimeLookup)
import Safe (readMay)
import Text.Printf (printf)
import qualified Data.ByteString.Lazy as L
import Network.HTTP.Types
import System.Random
import Network.HTTP.Conduit

httpRequest :: String -> IO L.ByteString
httpRequest u =
    responseBody <$> withManager
        (httpLbs (fromJust $ parseUrl u){responseTimeout = Just 15000000})

delimit :: Char -> String -> [String]
delimit _ [] = []
delimit a b =
    case break (==a) b of
        (c, []) -> [c]
        (c, (_:d)) -> c : delimit a d

-- from mime-mail
-- | Generates a random sequence of alphanumerics of the given length.
randomString :: RandomGen d => Int -> d -> (String, d)
randomString len =
    first (map toChar) . sequence' (replicate len (randomR (0, 61)))
  where
    sequence' [] g = ([], g)
    sequence' (f:fs) g =
        let (f', g') = f g
            (fs', g'') = sequence' fs g'
         in (f' : fs', g'')
    toChar i
        | i < 26 = toEnum $ i + fromEnum 'A'
        | i < 52 = toEnum $ i + fromEnum 'a' - 26
        | otherwise = toEnum $ i + fromEnum '0' - 52

randomBoundary :: IO L.ByteString
randomBoundary = do
    dashlen <- randomRIO (5, 30)
    charlen <- randomRIO (10, 30)
    fromString . (replicate dashlen '-' ++) <$> getStdRandom (randomString charlen)

type AntigateKey = String

type CaptchaID = Int

-- | See <http://antigate.com/panel.php?action=api>
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

data Field = Part L.ByteString L.ByteString
           | File L.ByteString L.ByteString L.ByteString L.ByteString
    deriving (Show)

instance Default CaptchaConf where
    def = CaptchaConf {phrase = False
                      ,regsense = False
                      ,numeric = Nothing
                      ,calc = False
                      ,min_len = 0
                      ,max_len = 0
                      ,is_russian = False
                      ,max_bid = Nothing
                      }

renderField :: L.ByteString -> Field -> L.ByteString
renderField boundary (Part name body) =
    "--" <> boundary <> "\r\n"
    <> "Content-Disposition: form-data; name=\"" <> name <> "\""
    <> "\r\n"
    <> "\r\n" <> body <> "\r\n"
renderField boundary (File name filename contenttype body) =
    "--" <> boundary <> "\r\n"
    <> "Content-Disposition: form-data; name=\"" <> name <> "\"; filename=\"" <> filename <> "\""
    <> "\r\n" <> "Content-Type: " <> contenttype <> "\r\n"
    <> "\r\n" <> body <> "\r\n"

renderFields :: L.ByteString -> [Field] -> L.ByteString
renderFields boundary fields =
    L.concat (map (renderField boundary) fields)
        <> "--" <> boundary <> "--\r\n"

captchaConfFields :: CaptchaConf -> [Field]
captchaConfFields c = catMaybes
        [bool "phrase" phrase
        ,bool "regsense" regsense
        ,tri "numeric" numeric
        ,bool "calc" calc
        ,num "min_len" min_len
        ,num "max_len" max_len
        ,bool "is_russian" is_russian
        ,Part "max_bid" . fromString . printf "%f" <$> max_bid c
        ]
    where fromBool False = "0"
          fromBool True = "1"
          fromTri Nothing = "0"
          fromTri (Just True) = "1"
          fromTri (Just False) = "2"
          optField :: Eq a => L.ByteString -> (a -> L.ByteString) -> (CaptchaConf -> a) -> Maybe Field
          optField name conv rec
            | rec c /= rec def = Just $ Part name $ conv $ rec c
            | otherwise = Nothing
          bool name = optField name fromBool
          tri name = optField name fromTri
          num name = optField name (fromString . show)

-- | report bad captcha result
--
-- throws 'HttpException' on network errors.
reportBad :: AntigateKey -> CaptchaID -> IO ()
reportBad key captchaid =
    void $ httpRequest
        ("http://antigate.com/res.php?key="++ key ++"&action=reportbad&id=" ++ show captchaid)

-- | retrieve your current account balance
--
-- throws 'HttpException' on network errors.
getBalance :: AntigateKey -> IO Double
getBalance key =
    read . UTF8.toString <$> httpRequest
        ("http://antigate.com/res.php?key="++ key ++"&action=getbalance")

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
    | otherwise = fromMaybe (UPLOAD_ERROR_UNKNOWN s) $
                        UPLOAD_OK <$> (readMay =<< stripPrefix "OK|" s)

-- | upload captcha for recognition
--
-- throws 'HttpException' on network errors.
uploadCaptcha :: AntigateKey -> CaptchaConf -> FilePath -> L.ByteString -> IO UploadResult
uploadCaptcha key sets filename image = do
    boundary <- randomBoundary
    let req = (fromJust $ parseUrl "http://antigate.com/in.php")
            {method = methodPost
            ,requestHeaders = [(hContentType, S.concat $ L.toChunks $ "multipart/form-data; boundary=" <> boundary)]
            ,requestBody = RequestBodyLBS $ renderFields boundary $
                [Part "method" "post"
                ,Part "key" (fromString key)
                ] ++
                captchaConfFields sets ++
                [File "file" (UTF8.fromString filename)
                    (L.fromChunks [defaultMimeLookup (fromString filename)])
                    image
                ]
                }
    parseUploadResult . UTF8.toString . responseBody <$> withManager (httpLbs req)

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
checkCaptcha :: AntigateKey -> CaptchaID -> IO CheckResult
checkCaptcha key captchaid = do
    parseCheckResult . UTF8.toString <$> httpRequest
        ("http://antigate.com/res.php?key="++ key ++"&action=get&id="++ show captchaid)

-- | retrieve multiple captcha status
--
-- throws 'HttpException' on network errors.
checkCaptchas :: AntigateKey -> [CaptchaID] -> IO [CheckResult]
checkCaptchas key captchaids = do
    parseCheckResults . UTF8.toString <$> httpRequest
        ("http://antigate.com/res.php?key="++ key ++"&action=get&ids="++
            intercalate "," (map show captchaids))

data SolveException = SolveExceptionUpload UploadResult
                    | SolveExceptionCheck CaptchaID CheckResult
    deriving (Show, Typeable)

instance Exception SolveException

-- | High level function to solve captcha, blocks until answer is provided (about 2-10 seconds).
--
-- throws 'SolveException' or 'HttpException' when something goes wrong.
solveCaptcha :: Int -- ^ how much to sleep while waiting for available slot. Microseconds.
             -> Int -- ^ how much to sleep between captcha checks. Microseconds.
             -> AntigateKey
             -> CaptchaConf
             -> FilePath -- ^ image filename (antigate guesses filetype by file extension)
             -> L.ByteString -- ^ image contents
             -> IO (CaptchaID, String)
solveCaptcha sleepwait sleepcaptcha key conf filename image = goupload
  where goupload = do
            ur <- uploadCaptcha key conf filename image
            case ur of
                ERROR_NO_SLOT_AVAILABLE -> do
                    threadDelay sleepwait
                    goupload
                UPLOAD_OK i -> gocheck i
                a -> throwIO $ SolveExceptionUpload a
        gocheck captchaid = do
            threadDelay sleepcaptcha
            res <- checkCaptcha key captchaid
            case res of
                CHECK_OK answer ->
                    return (captchaid, answer)
                CAPCHA_NOT_READY -> do
                    threadDelay sleepcaptcha
                    gocheck captchaid
                ex -> throwIO $ SolveExceptionCheck captchaid ex

-- | Same as 'solveCaptcha', but read contents from a file.
solveCaptchaFromFile :: Int -> Int -> AntigateKey -> CaptchaConf -> FilePath -> IO (CaptchaID, String)
solveCaptchaFromFile a b c d f = solveCaptcha a b c d f =<< L.readFile f
