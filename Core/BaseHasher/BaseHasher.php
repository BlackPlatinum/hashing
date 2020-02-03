<?php

/**
 * @author  BlackPlatinum Developers
 * @license MIT
 * Date: 31/Jan/2020 00:17 AM
 *
 * Base hasher class
 **/

namespace BlackPlatinum\Hashing\Core\BaseHasher;


abstract class BaseHasher
{

    // Constructor
    protected function __construct()
    {
        //
    }


    // Making hash
    protected static abstract function makeHash($data, array $options);


    // Verifying hash
    protected static abstract function verifyHash($data, $hash);


    // Checking if data needs rehash
    protected static abstract function needsRehash($hash, array $options);


    // Getting information about made hash
    protected static abstract function hashInfo($hash);
}