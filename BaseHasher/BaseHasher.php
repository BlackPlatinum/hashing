<?php

/**
 * @author  BlackPlatinum Developers
 * @license MIT
 * Date: 31/Jan/2020 00:17 AM
 *
 * Base hasher class
 **/

namespace BlackPlatinum\Hashing\BaseHasher;


abstract class BaseHasher
{

    // Constructor
    protected function __construct()
    {
        //
    }


    // Making hash
    protected abstract function makeHash($data, $algorithm, array $options);


    // Verifying hash
    protected abstract function verifyHash($data, $hash);


    // Checking if data needs rehash
    protected abstract function needsRehash($hash, $algorithm, array $options);


    // Getting information about made hash
    protected abstract function hashInfo($hash);
}