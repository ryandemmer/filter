<?php

/**
 * Part of the Joomla Framework Filter Package
 *
 * @copyright  Copyright (C) 2005 - 2021 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\Filter;

use Joomla\String\StringHelper;

/**
 * InputFilter is a class for filtering input from any data source
 *
 * Forked from the php input filter library by: Daniel Morris <dan@rootcube.com>
 * Original Contributors: Gianpaolo Racca, Ghislain Picard, Marco Wandschneider, Chris Tobin and Andrew Eddie.
 *
 * @since  1.0
 */
class InputFilter
{
    /**
     * Defines the InputFilter instance should only allow the supplied list of HTML tags.
     *
     * @var    integer
     * @since  1.4.0
     */
    public const ONLY_ALLOW_DEFINED_TAGS = 0;

    /**
     * Defines the InputFilter instance should block the defined list of HTML tags and allow all others.
     *
     * @var    integer
     * @since  1.4.0
     */
    public const ONLY_BLOCK_DEFINED_TAGS = 1;

    /**
     * Defines the InputFilter instance should only allow the supplied list of attributes.
     *
     * @var    integer
     * @since  1.4.0
     */
    public const ONLY_ALLOW_DEFINED_ATTRIBUTES = 0;

    /**
     * Defines the InputFilter instance should block the defined list of attributes and allow all others.
     *
     * @var    integer
     * @since  1.4.0
     */
    public const ONLY_BLOCK_DEFINED_ATTRIBUTES = 1;

    /**
     * The array of permitted tags.
     *
     * @var    array
     * @since  1.0
     */
    public $tagsArray;

    /**
     * The array of permitted tag attributes.
     *
     * @var    array
     * @since  1.0
     */
    public $attrArray;

    /**
     * The method for sanitising tags
     *
     * @var    integer
     * @since  1.0
     */
    public $tagsMethod;

    /**
     * The method for sanitising attributes
     *
     * @var    integer
     * @since  1.0
     */
    public $attrMethod;

    /**
     * A flag for XSS checks. Only auto clean essentials = 0, Allow clean blocked tags/attr = 1
     *
     * @var    integer
     * @since  1.0
     */
    public $xssAuto;

    /**
     * The list the blocked tags for the instance.
     *
     * @var    string[]
     * @since  1.0
     */
    public $blockedTags = [
        'applet',
        'body',
        'bgsound',
        'base',
        'basefont',
        'canvas',
        'embed',
        'frame',
        'frameset',
        'head',
        'html',
        'id',
        'iframe',
        'ilayer',
        'layer',
        'link',
        'meta',
        'name',
        'object',
        'script',
        'style',
        'title',
        'xml',
    ];

    /**
     * The list of blocked tag attributes for the instance.
     *
     * @var    string[]
     * @since  1.0
     */
    public $blockedAttributes = [
        'action',
        'background',
        'codebase',
        'dynsrc',
        'formaction',
        'lowsrc',
    ];

    /**
     * A special list of blocked characters.
     *
     * @var    string[]
     * @since  1.3.3
     */
    private $blockedChars = [
        '&tab;',
        '&space;',
        '&colon;',
        '&column;',
    ];

    /**
     * List of standard HTML boolean attributes.
     * These are allowed to appear without a value (e.g. <input disabled>).
     * Presence alone implies a true value.
     *
     * Includes attributes for:
     * - Forms (e.g. checked, disabled, readonly)
     * - Media (e.g. autoplay, controls, muted)
     * - Scripting (e.g. async, defer)
     * - Structural (e.g. hidden, open)
     * - Legacy/deprecated (e.g. compact, noresize)
     */
    private $booleanAttributes = [
        // Common HTML5 boolean attributes
        'allowfullscreen', 'async', 'autofocus', 'autoplay', 'checked',
        'controls', 'default', 'defer', 'disabled', 'formnovalidate',
        'hidden', 'inert', 'ismap', 'itemscope', 'loop', 'multiple',
        'muted', 'nomodule', 'novalidate', 'open', 'readonly', 'required',
        'reversed', 'selected', 'truespeed',

        // Deprecated or legacy boolean attributes
        'compact', 'declare', 'nohref', 'noresize', 'noshade', 'nowrap', 'scoped'
    ];

    /**
     * Constructor for InputFilter class.
     *
     * @param   array    $tagsArray   List of permitted HTML tags
     * @param   array    $attrArray   List of permitted HTML tag attributes
     * @param   integer  $tagsMethod  Method for filtering tags, should be one of the `ONLY_*_DEFINED_TAGS` constants
     * @param   integer  $attrMethod  Method for filtering attributes, should be one of the `ONLY_*_DEFINED_ATTRIBUTES` constants
     * @param   integer  $xssAuto     Only auto clean essentials = 0, Allow clean blocked tags/attributes = 1
     *
     * @since   1.0
     */
    public function __construct(
        array $tagsArray = [],
        array $attrArray = [],
        $tagsMethod = self::ONLY_ALLOW_DEFINED_TAGS,
        $attrMethod = self::ONLY_ALLOW_DEFINED_ATTRIBUTES,
        $xssAuto = 1
    ) {
        // Make sure user defined arrays are in lowercase
        $tagsArray = array_map('strtolower', (array) $tagsArray);
        $attrArray = array_map('strtolower', (array) $attrArray);

        // Assign member variables
        $this->tagsArray  = $tagsArray;
        $this->attrArray  = $attrArray;
        $this->tagsMethod = $tagsMethod;
        $this->attrMethod = $attrMethod;
        $this->xssAuto    = $xssAuto;
    }

    /**
     * Cleans the given input source based on the instance configuration and specified data type
     *
     * @param   string|string[]|object  $source  Input string/array-of-string/object to be 'cleaned'
     * @param   string                  $type    The return type for the variable:
     *                                           INT:       An integer
     *                                           UINT:      An unsigned integer
     *                                           FLOAT:     A floating point number
     *                                           BOOLEAN:   A boolean value
     *                                           WORD:      A string containing A-Z or underscores only (not case sensitive)
     *                                           ALNUM:     A string containing A-Z or 0-9 only (not case sensitive)
     *                                           CMD:       A string containing A-Z, 0-9, underscores, periods or hyphens (not case
     *                                                      sensitive)
     *                                           BASE64:    A string containing A-Z, 0-9, forward slashes, plus or equals (not case
     *                                                      sensitive)
     *                                           STRING:    A fully decoded and sanitised string (default)
     *                                           HTML:      A sanitised string
     *                                           ARRAY:     An array
     *                                           PATH:      A sanitised file path
     *                                           TRIM:      A string trimmed from normal, non-breaking and multibyte spaces
     *                                           USERNAME:  Do not use (use an application specific filter)
     *                                           RAW:       The raw string is returned with no filtering
     *                                           unknown:   An unknown filter will act like STRING. If the input is an array it will
     *                                                      return an array of fully decoded and sanitised strings.
     *
     * @return  mixed  'Cleaned' version of the `$source` parameter
     *
     * @since   1.0
     */
    public function clean($source, $type = 'string')
    {
        $type = ucfirst(strtolower($type));

        if ($type === 'Array') {
            return (array) $source;
        }

        if ($type === 'Raw') {
            return $source;
        }

        if (\is_array($source)) {
            $result = [];

            foreach ($source as $key => $value) {
                $result[$key] = $this->clean($value, $type);
            }

            return $result;
        }

        if (\is_object($source)) {
            foreach (get_object_vars($source) as $key => $value) {
                $source->$key = $this->clean($value, $type);
            }

            return $source;
        }

        $method = 'clean' . $type;

        if (method_exists($this, $method)) {
            return $this->$method((string) $source);
        }

        // Unknown filter method
        if (\is_string($source) && !empty($source)) {
            // Filter source for XSS and other 'bad' code etc.
            return $this->cleanString($source);
        }

        // Not an array or string... return the passed parameter
        return $source;
    }

    /**
     * Function to determine if contents of an attribute are safe
     *
     * @param   array  $attrSubSet  A 2 element array for attribute's name, value
     *
     * @return  boolean  True if bad code is detected
     *
     * @since   1.0
     */
    public static function checkAttribute($attrSubSet)
    {
        $attrSubSet[0] = strtolower($attrSubSet[0]);
        $attrSubSet[1] = html_entity_decode(strtolower($attrSubSet[1]), ENT_QUOTES | ENT_HTML401, 'UTF-8');

        return (strpos($attrSubSet[1], 'expression') !== false && $attrSubSet[0] === 'style')
            || preg_match('/(?:(?:java|vb|live)script|behaviour|mocha)(?::|&colon;|&column;)/', $attrSubSet[1]) !== 0;
    }

    /**
     * Internal method to iteratively remove all unwanted tags and attributes
     *
     * @param   string  $source  Input string to be 'cleaned'
     *
     * @return  string  'Cleaned' version of input parameter
     *
     * @since   1.0
     */
    protected function remove($source)
    {
        // Iteration provides nested tag protection
        do {
            $temp   = $source;
            $source = $this->cleanTags($source);
        } while ($temp !== $source);

        return $source;
    }

    /**
     * Internal method to strip a string of disallowed tags
     *
     * @param   string  $source  Input string to be 'cleaned'
     *
     * @return  string  'Cleaned' version of input parameter
     *
     * @since   1.0
     */
    protected function cleanTags($source)
    {
        $source = $this->escapeAttributeValues($source);
        $preTag = '';
        $postTag = $source;
        $voidTags = ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr'];

        while (($tagOpenStart = StringHelper::strpos($postTag, '<')) !== false) {
            $preTag .= StringHelper::substr($postTag, 0, $tagOpenStart);
            $postTag = StringHelper::substr($postTag, $tagOpenStart);
            $fromTagOpen = StringHelper::substr($postTag, 1);
            $tagOpenEnd = StringHelper::strpos($fromTagOpen, '>');

            if ($tagOpenEnd === false) {
                $preTag .= $postTag;
                break;
            }

            $currentTag = StringHelper::substr($fromTagOpen, 0, $tagOpenEnd);
            $tagLength = StringHelper::strlen($currentTag);
            $tagLeft = $currentTag;
            $attrSet = [];
            $currentSpace = StringHelper::strpos($tagLeft, ' ');

            $isCloseTag = false;
            if (StringHelper::substr($currentTag, 0, 1) === '/') {
                $isCloseTag = true;
                $tagName = StringHelper::substr(explode(' ', $currentTag)[0], 1);
            } else {
                $tagName = explode(' ', $currentTag)[0];
            }

            if (!preg_match('/^[a-z][a-z0-9]*$/i', $tagName) || (!$tagName) || ($this->xssAuto && in_array(strtolower($tagName), $this->blockedTags))) {
                $postTag = StringHelper::substr($postTag, $tagLength + 2);
                continue;
            }

            while ($currentSpace !== false) {
                $attr = '';
                $fromSpace = StringHelper::substr($tagLeft, $currentSpace + 1);
                $nextEqual = StringHelper::strpos($fromSpace, '=');
                $nextSpace = StringHelper::strpos($fromSpace, ' ');

                if ($nextEqual === false || ($nextSpace !== false && $nextSpace < $nextEqual)) {
                    $attr = $nextSpace === false ? trim($fromSpace) : StringHelper::substr($fromSpace, 0, $nextSpace);
                    $fromSpace = $nextSpace === false ? '' : StringHelper::substr($fromSpace, $nextSpace);
                } else {
                    $openQuotes = StringHelper::strpos($fromSpace, '"');
                    $closeQuotes = StringHelper::strpos($fromSpace, '"', $openQuotes + 1);

                    if ($openQuotes !== false && $closeQuotes !== false) {
                        $attr = StringHelper::substr($fromSpace, 0, $closeQuotes + 1);
                        $fromSpace = StringHelper::substr($fromSpace, $closeQuotes + 1);
                    } else {
                        $attr = $nextSpace === false ? trim($fromSpace) : StringHelper::substr($fromSpace, 0, $nextSpace);
                        $fromSpace = $nextSpace === false ? '' : StringHelper::substr($fromSpace, $nextSpace + 1);
                    }
                }

                if ($attr) {
                    $attrSet[] = trim($attr);
                }

                $currentSpace = StringHelper::strpos($fromSpace, ' ');
                if ($currentSpace === false && !empty(trim($fromSpace))) {
                    $attrSet[] = trim($fromSpace);
                }

                $tagLeft = $fromSpace;
            }

            $tagFound = in_array(strtolower($tagName), $this->tagsArray);

            if ((!$tagFound && $this->tagsMethod) || ($tagFound && !$this->tagsMethod)) {
                if (!$isCloseTag) {
                    $attrSet = $this->cleanAttributes($attrSet);
                    $preTag .= '<' . $tagName;

                    foreach ($attrSet as $attr) {
                        $preTag .= ' ' . $attr;
                    }

                    if (in_array($tagName, $voidTags, true)) {
                        $preTag = rtrim($preTag) . ' />';
                    } else {
                        $preTag .= '>';
                    }
                } else {
                    $preTag .= '</' . $tagName . '>';
                }
            }

            $postTag = StringHelper::substr($postTag, $tagLength + 2);
        }

        return $preTag . ($postTag !== '<' ? $postTag : '');
    }

    /**
	 * Internal method to strip a tag of disallowed attributes
	 *
	 * @param   array  $attrSet  Array of attribute pairs to filter
	 *
	 * @return  array  Filtered array of attribute pairs
	 *
	 * @since   1.0
	 */
	protected function cleanAttributes(array $attrSet)
    {
        $newSet = [];

        foreach ($attrSet as $rawAttr) {
            if (!$rawAttr) {
                continue;
            }

            $rawAttr = preg_replace('/\s*=\s*/', '=', trim($rawAttr));
            $attrSubSet = explode('=', $rawAttr, 2);
            $name = strtolower(trim(html_entity_decode($attrSubSet[0], ENT_QUOTES, 'UTF-8')));

            if (!preg_match('/^[\p{L}\p{N}_:-]+$/u', $name)) {
                continue;
            }

            if ($this->xssAuto && (in_array($name, $this->blockedAttributes) || StringHelper::strpos($name, 'on') === 0)) {
                continue;
            }

            $attrFound = in_array($name, $this->attrArray);
            $allow = (!$attrFound && $this->attrMethod) || ($attrFound && !$this->attrMethod);

            if (count($attrSubSet) === 2) {
                $value = trim($attrSubSet[1], "\"'");

                if (!StringHelper::strlen($value)) {
                    continue; // reject empty quoted value (not boolean)
                }

                $value = str_replace(['&#', "\n", "\r", '"'], '', stripslashes($value));

                if (static::checkAttribute([$name, $value])) {
                    continue;
                }

                if ($allow) {
                    $newSet[] = $name . '="' . $value . '"';
                }
            } elseif ($allow && in_array($name, $this->booleanAttributes, true)) {
                $newSet[] = $name;
            }
        }

        return $newSet;
    }

    /**
     * Try to convert to plaintext
     *
     * @param   string  $source  The source string.
     *
     * @return  string  Plaintext string
     *
     * @since   1.0
     * @deprecated  This method will be removed once support for PHP 5.3 is discontinued.
     */
    protected function decode($source)
    {
        return html_entity_decode($source, \ENT_QUOTES, 'UTF-8');
    }

    /**
     * Escape < > and " inside attribute values
     *
     * @param   string  $source  The source string.
     *
     * @return  string  Filtered string
     *
     * @since   1.0
     */
    protected function escapeAttributeValues($source)
    {
        $alreadyFiltered = '';
        $remainder       = $source;
        $badChars        = ['<', '"', '>'];
        $escapedChars    = ['&lt;', '&quot;', '&gt;'];

        // Process each portion based on presence of =" and "<space>, "/>, or ">
        // See if there are any more attributes to process
        while (preg_match('#<[^>]*?=\s*?(\"|\')#s', $remainder, $matches, \PREG_OFFSET_CAPTURE)) {
            $stringBeforeTag = substr($remainder, 0, $matches[0][1]);
            $tagPosition     = strlen($stringBeforeTag);

            // Get the character length before the attribute value
            $nextBefore = $tagPosition + strlen($matches[0][0]);

            // Figure out if we have a single or double quote and look for the matching closing quote
            // Closing quote should be "/>, ">, "<space>, or " at the end of the string
            $quote     = substr($matches[0][0], -1);
            $pregMatch = ($quote == '"') ? '#(\"\s*/\s*>|\"\s*>|\"\s+|\"$)#' : "#(\'\s*/\s*>|\'\s*>|\'\s+|\'$)#";

            // Get the portion after attribute value
            $attributeValueRemainder = substr($remainder, $nextBefore);

            if (preg_match($pregMatch, $attributeValueRemainder, $matches, \PREG_OFFSET_CAPTURE)) {
                $stringBeforeQuote = substr($attributeValueRemainder, 0, $matches[0][1]);
                $closeQuoteChars   = strlen($stringBeforeQuote);
                $nextAfter         = $nextBefore + $closeQuoteChars;
            } else {
                // No closing quote
                $nextAfter = strlen($remainder);
            }

            // Get the actual attribute value
            $attributeValue = substr($remainder, $nextBefore, $nextAfter - $nextBefore);

            // Escape bad chars
            $attributeValue = str_replace($badChars, $escapedChars, $attributeValue);
            $attributeValue = $this->stripCssExpressions($attributeValue);
            $alreadyFiltered .= substr($remainder, 0, $nextBefore) . $attributeValue . $quote;
            $remainder = substr($remainder, $nextAfter + 1);
        }

        // At this point, we just have to return the $alreadyFiltered and the $remainder
        return $alreadyFiltered . $remainder;
    }

    /**
     * Remove CSS Expressions in the form of <property>:expression(...)
     *
     * @param   string  $source  The source string.
     *
     * @return  string  Filtered string
     *
     * @since   1.0
     */
    protected function stripCssExpressions($source)
    {
        // Strip any comments out (in the form of /*...*/)
        $test = preg_replace('#\/\*.*\*\/#U', '', $source);

        // Test for :expression
        if (!stripos($test, ':expression')) {
            // Not found, so we are done
            return $source;
        }

        // At this point, we have stripped out the comments and have found :expression
        // Test stripped string for :expression followed by a '('
        if (preg_match_all('#:expression\s*\(#', $test, $matches)) {
            // If found, remove :expression
            return str_ireplace(':expression', '', $test);
        }

        return $source;
    }

    /**
     * Integer filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  integer  The filtered value
     */
    private function cleanInt($source)
    {
        $pattern = '/[-+]?[0-9]+/';

        preg_match($pattern, $source, $matches);

        return isset($matches[0]) ? (int) $matches[0] : 0;
    }

    /**
     * Alias for cleanInt()
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  integer  The filtered value
     */
    private function cleanInteger($source)
    {
        return $this->cleanInt($source);
    }

    /**
     * Unsigned integer filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  integer  The filtered value
     */
    private function cleanUint($source)
    {
        $pattern = '/[-+]?[0-9]+/';

        preg_match($pattern, $source, $matches);

        return isset($matches[0]) ? abs((int) $matches[0]) : 0;
    }

    /**
     * Float filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  float  The filtered value
     */
    private function cleanFloat($source)
    {
        $pattern = '/[-+]?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?/';

        preg_match($pattern, $source, $matches);

        return isset($matches[0]) ? (float) $matches[0] : 0.0;
    }

    /**
     * Alias for cleanFloat()
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  float  The filtered value
     */
    private function cleanDouble($source)
    {
        return $this->cleanFloat($source);
    }

    /**
     * Boolean filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  boolean  The filtered value
     */
    private function cleanBool($source)
    {
        return (bool) $source;
    }

    /**
     * Alias for cleanBool()
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  boolean  The filtered value
     */
    private function cleanBoolean($source)
    {
        return $this->cleanBool($source);
    }

    /**
     * Word filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanWord($source)
    {
        $pattern = '/[^A-Z_]/i';

        return preg_replace($pattern, '', $source);
    }

    /**
     * Alphanumerical filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanAlnum($source)
    {
        $pattern = '/[^A-Z0-9]/i';

        return preg_replace($pattern, '', $source);
    }

    /**
     * Command filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanCmd($source)
    {
        $pattern = '/[^A-Z0-9_\.-]/i';

        $result = preg_replace($pattern, '', $source);
        $result = ltrim($result, '.');

        return $result;
    }

    /**
     * Base64 filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanBase64($source)
    {
        $pattern = '/[^A-Z0-9\/+=]/i';

        return preg_replace($pattern, '', $source);
    }

    /**
     * String filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanString($source)
    {
        return $this->remove($this->decode($source));
    }

    /**
     * HTML filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanHtml($source)
    {
        return $this->remove($source);
    }

    /**
     * Path filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanPath($source)
    {
        $linuxPattern = '/^[A-Za-z0-9_\/-]+[A-Za-z0-9_\.-]*([\\\\\/]+[A-Za-z0-9_-]+[A-Za-z0-9_\.-]*)*$/';

        if (preg_match($linuxPattern, $source)) {
            return preg_replace('~/+~', '/', $source);
        }

        $windowsPattern = '/^([A-Za-z]:(\\\\|\/))?[A-Za-z0-9_-]+[A-Za-z0-9_\.-]*((\\\\|\/)+[A-Za-z0-9_-]+[A-Za-z0-9_\.-]*)*$/';

        if (preg_match($windowsPattern, $source)) {
            return preg_replace('~(\\\\|\/)+~', '\\', $source);
        }

        return '';
    }

    /**
     * Trim filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanTrim($source)
    {
        $result = trim($source);
        $result = StringHelper::trim($result, \chr(0xE3) . \chr(0x80) . \chr(0x80));
        $result = StringHelper::trim($result, \chr(0xC2) . \chr(0xA0));

        return $result;
    }

    /**
     * Username filter
     *
     * @param   string  $source  The string to be filtered
     *
     * @return  string  The filtered string
     */
    private function cleanUsername($source)
    {
        $pattern = '/[\x00-\x1F\x7F<>"\'%&]/';

        return preg_replace($pattern, '', $source);
    }
}
