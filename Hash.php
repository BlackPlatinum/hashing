<?php

/**
 * @author  BlackPlatinum Developers
 * @license MIT
 * Date: 31/Jan/2020 01:26 AM
 *
 * Main hasher class
 **/

namespace BlackPlatinum\Hashing;


use BlackPlatinum\Hashing\Core\BaseHasher\BaseHasher;
use BlackPlatinum\Hashing\Core\Exceptions\HashException;


class Hash extends BaseHasher
{

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
     */
    private function __construct()
    {
        parent::__construct();
    }


    /** Maps the algorithm name to an integer
     *
     * @param  string  $algorithmName
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
     * @param  string  $algorithm  The hash algorithm
     *
     * @return boolean Returns True if algorithm name is correct, False otherwise
     */
    private static function validateAlgorithm($algorithm)
    {
        return in_array($algorithm, self::supported(), true);
    }


    /** Makes hash from a data
     *
     * @param  mixed   $data       The data is being hashed
     * @param  string  $algorithm  The hash algorithm
     * @param  array   $options    An associative array containing options
     *
     * @return string Returns computed hash data
     * @throws HashException Throws exception if can not hash the data or can not detect the algorithm
     */
    public static function makeHash($data, $algorithm = "ARGON2ID", array $options = self::ARGON2_OPTIONS)
    {
        $algorithm = strtoupper($algorithm);
        if (!self::validateAlgorithm($algorithm)) {
            throw new HashException("Wrong algorithm name!");
        }
        $hash = password_hash((is_string($data) ? $data : json_encode($data)), self::mapper($algorithm),
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
     * @param  string  $hash       The computed hash
     * @param  string  $algorithm  The hash algorithm
     * @param  array   $options    An associative array containing options
     *
     * @return boolean Returns True if it needs rehash, False otherwise
     * @throws HashException Throws exception if can not detect the algorithm
     */
    public static function needsRehash($hash, $algorithm = "ARGON2ID", array $options = self::ARGON2_OPTIONS)
    {
        $algorithm = strtoupper($algorithm);
        if (!self::validateAlgorithm($algorithm)) {
            throw new HashException("Wrong algorithm name!");
        }
        return password_needs_rehash($hash, self::mapper($algorithm), $options);
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