<?php
/*-
 * #%L
 * Mobile ID sample PHP client
 * %%
 * Copyright (C) 2018 - 2019 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */
namespace Sk\Mid;
use HRobertson\X509Verify\SslCertificate;
use Sk\Mid\Exception\MidInternalErrorException;
use Sk\Mid\Exception\NotMidClientException;
use Sk\Mid\Exception\CertificateNotTrustedException;
use Sk\Mid\Rest\Dao\MidCertificate;
use Sk\Mid\Util\Logger;

class AuthenticationResponseValidator
{
    const TRUSTED_POLICY_IDENTIFIER_VALUES = [
        '1.3.6.1.4.1.10015.1.1',
        '1.3.6.1.4.1.10015.1.2',
        '1.3.6.1.4.1.51361.1.1.1',
        '1.3.6.1.4.1.51361.1.1.2',
        '1.3.6.1.4.1.51361.1.1.3',
        '1.3.6.1.4.1.51361.1.1.4',
        '1.3.6.1.4.1.51361.1.1.5',
        '1.3.6.1.4.1.51361.1.1.6',
        '1.3.6.1.4.1.51361.1.1.7',
        '1.3.6.1.4.1.51455.1.1.1',
    ];

    /** @var Logger $logger */
    private $logger;

    private $certificatePath = "/resources/trusted_certificates/";

    public function __construct()
    {
        $this->logger = new Logger('AuthenticationResponseValidator');
    }

    public function validate(Mobileidauthentication $authentication)
    {
        $this->validateAuthentication($authentication);
        $authenticationResult = new MobileIdAuthenticationResult();

        if (!$this->isResultOk($authentication)) {
            $authenticationResult->setValid(false);
            $authenticationResult->addError(MobileIdAuthenticationError::INVALID_RESULT);
            throw new MidInternalErrorException($authenticationResult->getErrorsAsString());
        }
        if ( !$this->verifyCertificateExpiry( $authentication->getCertificate() ) ) {
            $authenticationResult->setValid( false );
            $authenticationResult->addError( MobileIdAuthenticationError::CERTIFICATE_EXPIRED );
            throw new NotMidClientException();
        }
        if ( !$this->verifyCertificateTrusted( $authentication->getCertificateX509() ) ) {
            $authenticationResult->setValid( false );
            $authenticationResult->addError( MobileIdAuthenticationError::CERTIFICATE_NOT_TRUSTED );
            throw new CertificateNotTrustedException();
        }
        if ( !$this->verifyCertificatePolicyIdentityValue( $authentication->getCertificateX509() ) ) {
            $authenticationResult->setValid( false );
            $authenticationResult->addError( MobileIdAuthenticationError::CERTIFICATE_POLICY_IDENTIFIER_VALUE_NOT_TRUSTED );
            throw new CertificateNotTrustedException();
        }

        $identity = $authentication->constructAuthenticationIdentity();
        $authenticationResult->setAuthenticationIdentity($identity);

        return $authenticationResult;
    }

    private function validateAuthentication(Mobileidauthentication $authentication)
    {
        if (is_null($authentication->getCertificate())) {
            throw new MidInternalErrorException('Certificate is not present in the authentication response');
        } else if (empty($authentication->getSignatureValueInBase64())) {
            throw new MidInternalErrorException('Signature is not present in the authentication response');
        } else if (is_null($authentication->getHashType())) {
            throw new MidInternalErrorException('Hash type is not present in the authentication response');
        }
    }



    private function isResultOk(MobileIdAuthentication $authentication) : bool
    {
        return strcasecmp('OK', $authentication->getResult()) == 0;
    }

    private function verifyCertificateExpiry(MidCertificate $authenticationCertificate )
    {
        return $authenticationCertificate !== null && $authenticationCertificate->getValidTo() > time();
    }

    private function verifyCertificateTrusted($certificate )
    {
        foreach (array_diff(scandir(__DIR__.$this->certificatePath), array('.', '..')) as $file) {
            $caCertificate = file_get_contents(__DIR__.$this->certificatePath.$file);
            $caCert = new SslCertificate($caCertificate);
            $userCert = new SslCertificate($certificate['certificateAsString']);
            if ($userCert->isSignedBy($caCert)) {
                return true;
            }
        }
        return false;
    }

    private function verifyCertificatePolicyIdentityValue($certificate)
    {
        foreach (self::TRUSTED_POLICY_IDENTIFIER_VALUES as $value) {
            $certificatePolicy = 'Policy: ' . $value;

            if (preg_match("/$certificatePolicy$/m", $certificate['extensions']['certificatePolicies']) == 0) {
                return true;
            }
        }

        return false;
    }

}
