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
namespace Sk\Mid\Rest;

class MobileIdRestConnectorBuilder
{

    /** @var string $endpointUrl */
    private $endpointUrl;

    /** @var string $clientConfig */
    private $clientConfig;

    /** @var string $relyingPartyUUID */
    private $relyingPartyUUID;

    /** @var string $relyingPartyName */
    private $relyingPartyName;

    /** @var array $customHeaders */
    private $customHeaders = array();

    public function getEndpointUrl()
    {
        return $this->endpointUrl;
    }

    public function getClientConfig()
    {
        return $this->clientConfig;
    }

    public function getRelyingPartyUUID()
    {
        return $this->relyingPartyUUID;
    }

    public function getRelyingPartyName()
    {
        return $this->relyingPartyName;
    }

    /**
     * @return array
     */
    public function getCustomHeaders()
    {
        return $this->customHeaders;
    }

    public function withEndpointUrl(string $endpointUrl = null)
    {
        $this->endpointUrl = $endpointUrl;
        return $this;
    }

    public function withClientConfig(string $clientConfig = null)
    {
        $this->clientConfig = $clientConfig;
        return $this;
    }

    public function withRelyingPartyUUID(string $relyingPartyUUID = null)
    {
        $this->relyingPartyUUID = $relyingPartyUUID;
        return $this;
    }

    public function withRelyingPartyName(string $relyingPartyName = null)
    {
        $this->relyingPartyName = $relyingPartyName;
        return $this;
    }

    public function withCustomHeaders(array $customHeaders = null)
    {
        $this->customHeaders = $customHeaders;
        return $this;
    }

    public function build()
    {
        return new MobileIdRestConnector($this);
    }
}
