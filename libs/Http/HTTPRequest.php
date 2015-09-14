<?php
/**
 * Created by PhpStorm.
 * User: leo
 * Date: 15/9/13
 * Time: 下午3:37
 */

namespace PHPCrawler\Http;


use Curl\Curl;
use Exception;
use PHPCrawler\Enums\PHPCrawlerRequestErrors;
use PHPCrawler\PHPCrawlerBenchmark;
use PHPCrawler\PHPCrawlerCookieDescriptor;
use PHPCrawler\PHPCrawlerDNSCache;
use PHPCrawler\PHPCrawlerDocumentInfo;
use PHPCrawler\PHPCrawlerLinkFinder;
use PHPCrawler\PHPCrawlerResponseHeader;
use PHPCrawler\PHPCrawlerURLDescriptor;
use PHPCrawler\Utils\PHPCrawlerUtils;

class HTTPRequest
{
    public $userAgentString;
    private $DNSCache;
    private $LinkFinder;
    private $UrlDescriptor;
    private $url_parts;
    private $cookie_array;
    private $header_check_callback_function;
    private $post_data;
    private $proxy;
    private $request_gzip_content;
    private $lastResponseHeader;
    private $receive_content_types;
    private $receive_to_file_content_types;
    private $tmpFile;
    private $content_bytes_received;
    private $header_bytes_received;
    private $global_traffic_count;
    private $linksearch_content_types;
    private $content_buffer_size;
    private $chunk_buffer_size;
    private $socket_read_buffer_size;

    /**
     *
     */
    public function __construct()
    {
        // Init LinkFinder
        $this->LinkFinder = new PHPCrawlerLinkFinder();

        $this->DNSCache = new PHPCrawlerDNSCache();
        $this->curl = new Curl();
    }

    public function setUrl(PHPCrawlerURLDescriptor $UrlDescriptor)
    {
        $this->UrlDescriptor = $UrlDescriptor;

        // Split the URL into its parts
        $this->url_parts = PHPCrawlerUtils::splitURL($UrlDescriptor->url_rebuild);
    }

    /**
     * Adds a cookie to send with the request.
     *
     * @param string $name Cookie-name
     * @param string $value Cookie-value
     */
    public function addCookie($name, $value)
    {
        $this->cookie_array[$name] = $value;
    }

    /**
     * Adds a cookie to send with the request.
     *
     * @param PHPCrawlerCookieDescriptor $Cookie
     */
    public function addCookieDescriptor(PHPCrawlerCookieDescriptor $Cookie)
    {
        $this->addCookie($Cookie->name, $Cookie->value);
    }

    /**
     * Adds a bunch of cookies to send with the request
     *
     * @param array $cookies Numeric array containins cookies as PHPCrawlerCookieDescriptor-objects
     */
    public function addCookieDescriptors($cookies)
    {
        $cnt = count($cookies);
        for ($x = 0; $x < $cnt; $x++) {
            $this->addCookieDescriptor($cookies[$x]);
        }
    }

    /**
     * Removes all cookies to send with the request.
     */
    public function clearCookies()
    {
        $this->cookie_array = array();
    }

    /**
     * Sets the html-tags from which to extract/find links from.
     *
     * @param array $tag_array Numeric array containing the tags, i.g. array("href", "src", "url", ...)
     * @return bool
     */
    public function setLinkExtractionTags($tag_array)
    {
        if (!is_array($tag_array)) return false;

        $this->LinkFinder->extract_tags = $tag_array;
        return true;
    }

    /**
     * Specifies whether redirect-links set in http-headers should get searched for.
     *
     * @return bool
     */
    public function setFindRedirectURLs($mode)
    {
        if (!is_bool($mode)) return false;

        $this->LinkFinder->find_redirect_urls = $mode;

        return true;
    }

    /**
     * Adds post-data to send with the request.
     */
    public function addPostData($key, $value)
    {
        $this->post_data[$key] = $value;
    }

    /**
     * Removes all post-data to send with the request.
     */
    public function clearPostData()
    {
        $this->post_data = array();
    }

    public function setProxy($proxy_host, $proxy_port, $proxy_username = null, $proxy_password = null)
    {
        $this->proxy = array();
        $this->proxy["proxy_host"] = $proxy_host;
        $this->proxy["proxy_port"] = $proxy_port;
        $this->proxy["proxy_username"] = $proxy_username;
        $this->proxy["proxy_password"] = $proxy_password;
    }

    /**
     * Sets basic-authentication login-data for protected URLs.
     */
    public function setBasicAuthentication($username, $password)
    {
        $this->url_parts["auth_username"] = $username;
        $this->url_parts["auth_password"] = $password;
    }

    /**
     * Enables/disables aggresive linksearch
     *
     * @param bool $mode
     * @return bool
     */
    public function enableAggressiveLinkSearch($mode)
    {
        if (!is_bool($mode)) return false;

        $this->LinkFinder->aggressive_search = $mode;
        return true;
    }

    public function CheckCallbackFunction(&$obj, $method_name)
    {
        $this->header_check_callback_function = array($obj, $method_name);
    }

    public function requestGzipContent($mode)
    {
        if (is_bool($mode)) {
            $this->request_gzip_content = $mode;
        }
    }

    /**
     * Sets the temporary file to use when content of found documents should be streamed directly into a temporary file.
     *
     * @param string $tmp_file The TMP-file to use.
     * @return bool
     */
    public function setTmpFile($tmp_file)
    {
        //Check if writable
        $fp = @fopen($tmp_file, "w");

        if (!$fp) {
            return false;
        } else {
            fclose($fp);
            $this->tmpFile = $tmp_file;
            return true;
        }
    }

    public function setHeaderCheckCallbackFunction(&$obj, $method_name)
    {
        $this->header_check_callback_function = array($obj, $method_name);
    }

    /**
     * Sends the HTTP-request and receives the page/file.
     * @return PHPCrawlerDocumentInfo A PHPCrawlerDocumentInfo-object containing all information about the received page/file
     * @throws Exception
     */
    public function sendRequest()
    {
        // Prepare LinkFinder
        $this->LinkFinder->resetLinkCache();
        $this->LinkFinder->setSourceUrl($this->UrlDescriptor);

        // Initiate the Response-object and pass base-infos
        $PageInfo = new PHPCrawlerDocumentInfo();
        $PageInfo->url = $this->UrlDescriptor->url_rebuild;
        $PageInfo->protocol = $this->url_parts["protocol"];
        $PageInfo->host = $this->url_parts["host"];
        $PageInfo->path = $this->url_parts["path"];
        $PageInfo->file = $this->url_parts["file"];
        $PageInfo->query = $this->url_parts["query"];
        $PageInfo->port = $this->url_parts["port"];
        $PageInfo->url_link_depth = $this->UrlDescriptor->url_link_depth;

        $curl = new Curl();

        // HTTP protocol
        // Host
        // User-Agent
        $curl->setUserAgent($this->userAgentString);
        //Accept
        $curl->setHeader('Accept', '*/*');
        // Request GZIP-content
        if ($this->request_gzip_content == true) {
            $curl->setHeader('Accept-Encoding', 'gzip, deflate');
        }

        // Referer
        if ($this->UrlDescriptor->refering_url != null) {
            $curl->setReferer($this->UrlDescriptor->refering_url);
        }

        // Cookies
        if (!empty($this->cookie_array)) {
            @reset($this->cookie_array);
            while (list($name, $value) = each($this->cookie_array)) {
                $curl->setCookie($name, $value);
            }
        }

        // Authentication
        if ($this->url_parts["auth_username"] != "" && $this->url_parts["auth_password"] != "") {
            $curl->setBasicAuthentication($this->url_parts["auth_username"], $this->url_parts["auth_password"]);
        }

        // Proxy authentication
        if ($this->proxy != null && $this->proxy["proxy_username"] != null) {
            $auth_string = base64_encode($this->proxy["proxy_username"] . ":" . $this->proxy["proxy_password"]);
            $curl->setHeader('Proxy-Authorization', "Basic $auth_string");
        }
        $curl->setHeader('Connection', 'close');

        // Methode(GET or POST)

        $curl->beforeSend(function () {
            PHPCrawlerBenchmark::reset('curl_request');
            PHPCrawlerBenchmark::start('curl_request');
        });
        $curl->complete(function () use ($PageInfo) {
            $PageInfo->server_response_time = PHPCrawlerBenchmark::stop('curl_request');
        });
        if (count($this->post_data) > 0) {
            @reset($this->post_data);
            $curl->post($this->UrlDescriptor->url_rebuild, $this->post_data);
        } else {
            $curl->get($this->UrlDescriptor->url_rebuild);
        }

        // If error occured
        if ($curl->errorCode != 0) {
            $PageInfo->error_code = $curl->errorCode;
            $PageInfo->error_occured = true;
            $PageInfo->error_string = $curl->errorMessage;
            return $PageInfo;
        }
        $headerLength = strlen($curl->rawResponseHeaders);

        $contentLength = strlen($curl->rawResponse);

        $this->content_bytes_received = $contentLength;
        $this->global_traffic_count = $contentLength + $headerLength;

        // Read response-header
        $response_header = $curl->rawResponseHeaders;
        if ($headerLength > 0) {
            $this->LinkFinder->processHTTPHeader($response_header);
        }
        $this->lastResponseHeader = new PHPCrawlerResponseHeader($response_header, $this->UrlDescriptor->url_rebuild);

        $PageInfo->responseHeader = $this->lastResponseHeader;
        $PageInfo->header = $this->lastResponseHeader->header_raw;
        $PageInfo->http_status_code = $this->lastResponseHeader->http_status_code;
        $PageInfo->content_type = $this->lastResponseHeader->content_type;
        $PageInfo->cookies = $this->lastResponseHeader->cookies;

        // Referer-Infos
        if ($this->UrlDescriptor->refering_url != null) {
            $PageInfo->referer_url = $this->UrlDescriptor->refering_url;
            $PageInfo->refering_linkcode = $this->UrlDescriptor->linkcode;
            $PageInfo->refering_link_raw = $this->UrlDescriptor->link_raw;
            $PageInfo->refering_linktext = $this->UrlDescriptor->linktext;
        }

        // Check if content should be received
        $receive = $this->decideReceiveContent($this->lastResponseHeader);

        if ($receive == false) {
            $curl->close();
            $PageInfo->received = false;
            $PageInfo->links_found_url_descriptors = $this->LinkFinder->getAllURLs(); // Maybe found a link/redirect in the header
            $PageInfo->meta_attributes = $this->LinkFinder->getAllMetaAttributes();
            return $PageInfo;
        } else {
            $PageInfo->received = true;
        }

        // Check if content should be streamd to file
        $stream_to_file = $this->decideStreamToFile($response_header);

        // Read content
        $response_content = $curl->rawResponse;
        if (!empty($response_content)) {
            $this->LinkFinder->findLinksInHTMLChunk($response_content);
        }
        if ($stream_to_file) {
            $fp = @fopen($this->tmpFile, "w");

            if ($fp == false) {
                $PageInfo->error_code = PHPCrawlerRequestErrors::ERROR_TMP_FILE_NOT_WRITEABLE;
                $PageInfo->error_string = "Couldn't open the temporary file " . $this->tmpFile . " for writing.";
                $PageInfo->error_occured = true;
                return "";
            }
            @fwrite($fp, $response_content);
        }

        $curl->close();

        // Complete ResponseObject
        $PageInfo->content = $response_content;
        $PageInfo->source = &$PageInfo->content;
        $PageInfo->received_completly = $PageInfo->received_completely;

        if ($stream_to_file == true) {
            $PageInfo->received_to_file = true;
            $PageInfo->content_tmp_file = $this->tmpFile;
        } else $PageInfo->received_to_memory = true;

        $PageInfo->links_found_url_descriptors = $this->LinkFinder->getAllURLs();
        $PageInfo->meta_attributes = $this->LinkFinder->getAllMetaAttributes();

        // Info about received bytes
        $PageInfo->bytes_received = $this->content_bytes_received;
        $PageInfo->header_bytes_received = $this->header_bytes_received;


        $PageInfo->setLinksFoundArray();

        $this->LinkFinder->resetLinkCache();

        return $PageInfo;

    }

    /**
     * Checks whether the content of this page/file should be received (based on the content-type, http-status-code,
     * user-callback and the applied rules)
     *
     * @param PHPCrawlerResponseHeader $responseHeader The response-header as an PHPCrawlerResponseHeader-object
     * @return bool TRUE if the content should be received
     */
    private function decideReceiveContent(PHPCrawlerResponseHeader $responseHeader)
    {
        // Get Content-Type from header
        $content_type = $responseHeader->content_type;

        // Call user header-check-callback-method
        if ($this->header_check_callback_function != null) {
            $ret = call_user_func($this->header_check_callback_function, $responseHeader);
            if ($ret < 0) return false;
        }

        // No Content-Type given
        if ($content_type == null)
            return false;

        // Status-code not 2xx
        if ($responseHeader->http_status_code == null || $responseHeader->http_status_code > 299 || $responseHeader->http_status_code < 200)
            return false;

        // Check against the given content-type-rules
        $receive = PHPCrawlerUtils::checkStringAgainstRegexArray($content_type, $this->receive_content_types);

        return $receive;
    }

    private function decideStreamToFile($response_header)
    {
        if (count($this->receive_to_file_content_types) == 0) return false;

        // Get Content-Type from header
        $content_type = PHPCrawlerUtils::getHeaderValue($response_header, "content-type");

        // No Content-Type given
        if ($content_type == null) return false;

        // Check against the given rules
        $receive = PHPCrawlerUtils::checkStringAgainstRegexArray($content_type, $this->receive_to_file_content_types);

        return $receive;
    }


    /**
     * Adds a rule to the list of rules that decides which pages or files - regarding their content-type - should be received
     *
     * If the content-type of a requested document doesn't match with the given rules, the request will be aborted after the header
     * was received.
     *
     * @param string $regex The rule as a regular-expression
     * @return bool TRUE if the rule was added to the list.
     *              FALSE if the given regex is not valid.
     */
    public function addReceiveContentType($regex)
    {
        $check = PHPCrawlerUtils::checkRegexPattern($regex); // Check pattern

        if ($check == true) {
            $this->receive_content_types[] = trim(strtolower($regex));
        }
        return $check;
    }

    /**
     * Adds a rule to the list of rules that decides what types of content should be streamed diretly to the temporary file.
     *
     * If a content-type of a page or file matches with one of these rules, the content will be streamed directly into the temporary file
     * given in setTmpFile() without claiming local RAM.
     *
     * @param string $regex The rule as a regular-expression
     * @return bool         TRUE if the rule was added to the list and the regex is valid.
     */
    public function addStreamToFileContentType($regex)
    {
        $check = PHPCrawlerUtils::checkRegexPattern($regex); // Check pattern

        if ($check == true) {
            $this->receive_to_file_content_types[] = trim($regex);
        }
        return $check;
    }

    /**
     * Sets the size-limit in bytes for content the request should receive.
     *
     * @param int $bytes
     * @return bool
     */
    public function setContentSizeLimit($bytes)
    {
        if (preg_match("#^[0-9]*$#", $bytes)) {
            $this->content_size_limit = $bytes;
            return true;
        } else return false;
    }

    /**
     * Returns the global traffic this instance of the HTTPRequest-class caused so far.
     *
     * @return int The traffic in bytes.
     */
    public function getGlobalTrafficCount()
    {
        return $this->global_traffic_count;
    }

    /**
     * Adds a rule to the list of rules that decide what kind of documents should get
     * checked for links in (regarding their content-type)
     *
     * @param string $regex Regular-expression defining the rule
     * @return bool         TRUE if the rule was successfully added
     */
    public function addLinkSearchContentType($regex)
    {
        $check = PHPCrawlerUtils::checkRegexPattern($regex); // Check pattern
        if ($check == true) {
            $this->linksearch_content_types[] = trim($regex);
        }
        return $check;
    }

    /**
     * Sets the http protocol version to use for requests
     *
     * @param int $http_protocol_version One of the PHPCrawlerHTTPProtocols-constants, or
     *                                   1 -> HTTP 1.0
     *                                   2 -> HTTP 1.1
     */
    public function setHTTPProtocolVersion($http_protocol_version)
    {
        if (preg_match("#[1-2]#", $http_protocol_version)) {
            $this->http_protocol_version = $http_protocol_version;
            return true;
        } else return false;
    }

    /**
     * Defines the sections of a document that will get ignroed by the internal link-finder.
     *
     * @param int $document_sections Bitwise combination of the {@link PHPCrawlerLinkSearchDocumentSections}-constants.
     */
    public function excludeLinkSearchDocumentSections($document_sections)
    {
        return $this->LinkFinder->excludeLinkSearchDocumentSections($document_sections);
    }

    /**
     * Adjusts some internal buffer-sizes of the HTTPRequest-class
     *
     * @param int $content_buffer_size content_buffer_size in bytes or NULL if not to change this value.
     * @param int $chunk_buffer_size chunk_buffer_size in bytes or NULL if not to change this value.
     * @param int $socket_read_buffer_size socket_read_buffer_sizein bytes or NULL if not to change this value.
     * @param int $source_overlap_size source_overlap_size in bytes or NULL if not to change this value.
     */
    public function setBufferSizes($content_buffer_size = null, $chunk_buffer_size = null, $socket_read_buffer_size = null, $source_overlap_size = null)
    {
        if ($content_buffer_size !== null)
            $this->content_buffer_size = $content_buffer_size;

        if ($chunk_buffer_size !== null)
            $this->chunk_buffer_size = $chunk_buffer_size;

        if ($socket_read_buffer_size !== null)
            $this->socket_read_buffer_size = $socket_read_buffer_size;

        if ($source_overlap_size !== null)
            $this->source_overlap_size = $source_overlap_size;

        if ($this->content_buffer_size < $this->chunk_buffer_size || $this->chunk_buffer_size < $this->socket_read_buffer_size) {
            throw new Exception("Implausible buffer-size-settings assigned to " . get_class($this) . ".");
        }
    }
}