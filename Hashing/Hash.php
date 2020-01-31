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
    private $algorithm;

    /**
     * @var array Map array
     */
    private $map = ["BCRYPT" => 1, "ARGON2I" => 2, "ARGON2ID" => 3];

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
        $this->algorithm = strtoupper($algorithm);
    }


    /** Maps the algorithm name to an integer
     *
     * @param $algorithmName
     *
     * @return integer
     */
    private function mapper($algorithmName)
    {
        return $this->map[$algorithmName];
    }


    /**
     * Validates the algorithm name
     *
     * @return boolean Returns True if algorithm name is correct, False otherwise
     */
    private function validateAlgorithm()
    {
        return in_array($this->algorithm, self::supported(), true);
    }


    /** Makes hash from a data
     *
     * @param  mixed  $data     The data is being hashed
     * @param  array  $options  An associative array containing options
     *
     * @return string Returns computed hash data
     * @throws HashException Throws exception if can not hash the data
     */
    public function makeHash($data, array $options = self::ARGON2_OPTIONS)
    {
        if (!$this->validateAlgorithm()) {
            throw new HashException("Wrong algorithm name!");
        }
        $hash = password_hash((is_string($data) ? $data : json_encode($data)), self::mapper($this->algorithm),
                $options);
        if (!$hash) {
            throw new HashException("Could not hash the data!");
        }
        return $hash;
    }


    /** Verify hash authenticity
     *
     * @param  mixed   $data  The data is being hashed
     * @param  string  $hash  The computed hash
     *
     * @return boolean Returns True if hash is verified, False otherwise
     */
    public function verifyHash($data, $hash)
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
    public function needsRehash($hash, array $options = self::ARGON2_OPTIONS)
    {
        return password_needs_rehash($hash, $this->mapper($this->algorithm), $options);
    }


    /**
     * Returns hash information
     *
     * @param  string  $hash  The computed hash
     *
     * @return array Returns hash information
     */
    public function hashInfo($hash)
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