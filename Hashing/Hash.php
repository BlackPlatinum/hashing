<?php

/**
 * @author  BlackPlatinum Developers
 * @license MIT
 * Date: 31/Jan/2020 01:26 AM
 *
 * Main hasher class
 **/

namespace BlackPlatinum\Hashing\Hashing;


use BlackPlatinum\Hashing\Core\BaseHasher\BaseHasher;
use BlackPlatinum\Hashing\Core\Exceptions\HashException;


class Hash extends BaseHasher
{

    /**
     * @var string The hash algorithm
     */
    private static $algorithm;

    /**
     * @var array Map array
     */
    private static $map = ["BCRYPT" => 1, "ARGON2I" => 2, "ARGON2ID" => 3];

    /**
     * @var array Default BCRYPT options
     */
    public const BCRYPT_OPTIONS = ["cost" => 12];

    /**
     * @var array Default ARGON2 options
     */
    public const ARGON2_OPTIONS = ["time_cost" => 6, "memory_cost" => 98304];


    /**
     * Constructor
     *
     * @param  string  $algorithm  The algorithm name <p> The default algorithm is ARGON2ID
     */
    public function __construct($algorithm = "ARGON2ID")
    {
        parent::__construct();
        self::$algorithm = strtoupper($algorithm);
    }


    /** Maps the algorithm name to an integer
     *
     * @param $algorithmName
     *
     * @return integer
     */
    private static function mapper($algorithmName)
    {
        return self::$map[$algorithmName];
    }


    /**
     * Validates the algorithm name
     *
     * @return boolean Returns True if algorithm name is correct, False otherwise
     */
    private static function validateAlgorithm()
    {
        return in_array(self::$algorithm, self::supported(), true);
    }


    /**
     * Set the algorithm name <p> The default algorithm is ARGON2ID
     *
     * @param  string  $algorithm  The algorithm name
     *
     * @return Hash Returns a new instance of Hash
     */
    public static function setHashAlgorithm($algorithm = "ARGON2ID")
    {
        return new Hash($algorithm);
    }


    /**
     * Returns the algorithm name
     *
     * @return string Returns the algorithm name
     */
    public static function getHashAlgorithm()
    {
        return self::$algorithm;
    }


    /** Makes hash from a data
     *
     * @param  mixed  $data     The data is being hashed
     * @param  array  $options  An associative array containing options
     *
     * @return string Returns computed hash data
     * @throws HashException Throws exception if can not hash the data
     */
    public static function makeHash($data, array $options = self::ARGON2_OPTIONS)
    {
        if (!self::validateAlgorithm()) {
            throw new HashException("Wrong algorithm name!");
        }
        $hash = password_hash((is_string($data) ? $data : json_encode($data)), self::mapper(self::$algorithm),
                $options);
        if (!$hash) {
            throw new HashException("Could not hash the data!");
        }
        return $hash;
    }


    /** Verifies hash authenticity
     *
     * @param  mixed   $data  The data is being hashed
     * @param  string  $hash  The computed hash
     *
     * @return boolean Returns True if hash is verified, False otherwise
     */
    public static function verifyHash($data, $hash)
    {
        return password_verify((is_string($data) ? $data : json_encode($data)), $hash);
    }


    /**
     * Checks if data needs rehash or not
     *
     * @param  string  $hash     The computed hash
     * @param  array   $options  An associative array containing options
     *
     * @return boolean Returns True if it needs rehash, False otherwise
     */
    public static function needsRehash($hash, array $options = self::ARGON2_OPTIONS)
    {
        return password_needs_rehash($hash, self::mapper(self::$algorithm), $options);
    }


    /**
     * Returns the hash information
     *
     * @param  string  $hash  The computed hash
     *
     * @return array Returns the hash information
     */
    public static function hashInfo($hash)
    {
        return password_get_info($hash);
    }


    /**
     * Returns supported algorithms
     *
     * @return array Returns supported algorithms
     */
    public static function supported()
    {
        return [
                "BCRYPT",
                "ARGON2I",
                "ARGON2ID"
        ];
    }
}