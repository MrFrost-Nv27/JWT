<?php

namespace Mrfrost\JWT\Config;

use CodeIgniter\Config\BaseConfig;

class JWT extends BaseConfig
{
    /**
     * --------------------------------------------------------------------------
     * JWT Issuer
     * --------------------------------------------------------------------------
     * Set Issuer of JWT for payload
     */
    public string $issuer = 'Shield';

    /**
     * --------------------------------------------------------------------------
     * Encryption Key
     * --------------------------------------------------------------------------
     *
     * There is two way to set the encryption key
     * set in $encryptionKey or get the string by file content
     *
     * If $encryptionKey is set, the string is used
     * otherwise, used the file content.
     * 
     * @var string $encryptionKey
     */
    public $encryptionKey = "SSwnNIDzWzz-jEdFU271ylPygJ9TbNK0Ryfw7vxzRWQifxcCydJraNqwQ6fx7-hMditLPMZtEmDPyLJRoJHFMLmf_Pv3Qv5ZucTfaiyAtTyZ2yuAlmfCrjnirsVkSHZspZr1DrswlQazJcTG9TRtjHrM5Lf6GWSfqTImeZUxDoMHB3aT6Xp_vF4CZjYMeJPEB0hzTk7CCgRxt-c9mYRHtT6GKdfqLTKwOxb3goBoZki6BnRtEzAlUWMEaHQ83lI_ShOg2xe27iCcY9dxB1DtTR3pnKYIiKnxJfuL12mbnSV9rE5P0gX0TdHwghC_dK7vB3HsYbU4B0i7DzlxZJPiuQ";
    public string $keyFilesPath = ROOTPATH;
    public string $keyFilesName = 'key';

    /**
     * --------------------------------------------------------------------
     * Unused Token Lifetime
     * --------------------------------------------------------------------
     * Determines the amount of time, in seconds, that an unused
     * access token can be used.
     */
    public int $unusedTokenLifetime = YEAR;

    /**
     * --------------------------------------------------------------------
     * JSON Web Encryption Utils
     * --------------------------------------------------------------------
     * Algorithm and method that JWE Needed
     */
    public string $JWEKeyEncryptionAlgorithm        = 'A256KW';
    public string $JWEContentEncryptionAlgorithm    = 'A256CBC-HS512';
    public string $JWECompressionMethod             = 'DEF';
}