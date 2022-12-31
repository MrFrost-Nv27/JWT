<?php

namespace Mrfrost\JWT\Enums;

enum AlgorithmType: string
{
    /**
     * Available JWT Service Algorithm
     * 
     * You can Change the value
     * But Don't change the case set
     */
    case DSA = "digital_signature_algorithm";
    case KEA = "key_encryption_algorithm";
    case CEA = "content_encryption_algorithm";
}