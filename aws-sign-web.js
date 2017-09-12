const crypto = require('crypto')
const parseUrl = require('url').parse
const extend = require('deep-extend')

//
// AWS Signature v4 Implementation
//
// Copyright (c) 2017 Tradle, Inc
//
// Distributed under MIT license. (See file LICENSE)
//
//
// Copyright (c) 2016 Daniel Joos
//
// Distributed under MIT license. (See file LICENSE)
//

const defaultConfig = {
    region: 'eu-west-1',
    service: 'execute-api',
    defaultContentType: 'application/json',
    defaultAcceptType: 'application/json',
    defaultExpectType: '100-continue',
    payloadSerializerFactory: () => obj => JSON.stringify(obj),
    hasherFactory: () => ({ hash: sha256 })
}

/**
 * Create a new signer object with the given configuration.
 * Configuration must specify the AWS credentials used for the signing operation.
 * It must contain the following properties:
 * `accessKeyId`: The AWS IAM access key ID.
 * `secretAccessKey`: The AWS IAM secret key.
 * `sessionToken`: Optional session token, required for temporary credentials.
 * @param {object} config The configuration object.
 * @constructor
 */
const AwsSigner = function (config) {
    this.config = extend({}, defaultConfig, config)
    assert(this.config.accessKeyId, 'AwsSigner requires AWS AccessKeyID')
    assert(this.config.secretAccessKey, 'AwsSigner requires AWS SecretAccessKey')
    this.payloadSerializer = this.config.payloadSerializer ||
        this.config.payloadSerializerFactory()
    this.hasher = this.config.hasherFactory()
}

/**
 * Create signature headers for the given request.
 * Request must be in the format, known from the `$http` service of Angular:
 * ```
 * request = {
 *      headers: { ... },
 *      method: 'GET',
 *      url: 'http://...',
 *      params: { ... },
 *      data: ...           // alternative: body
 * }
 * ```
 * The resulting object contains the signature headers. For example, it can be merged into an
 * existing `$http` config when dealing with Angular JS.
 * @param {object} request The request to create the signature for. Will not be modified!
 * @param {Date=} signDate Optional signature date to use. Current date-time is used if not specified.
 * @returns Signed request headers.
 */
AwsSigner.prototype.sign = function (request, signDate) {
    const uri = parseUrl(request.url)
    if (!uri.query) uri.query = {}
    const workingSet = {
        request: extend({}, request),
        signDate: signDate || new Date(),
        uri
    }

    prepare(this, workingSet)
    buildCanonicalRequest(this, workingSet)    // Step1: build the canonical request
    buildStringToSign(this, workingSet)        // Step2: build the string to sign
    calculateSignature(this, workingSet)       // Step3: calculate the signature hash
    buildSignatureHeader(this, workingSet)     // Step4: build the authorization header
    return {
        'accept': workingSet.request.headers['accept'],
        'expect': workingSet.request.headers['expect'],
        'authorization': workingSet.authorization,
        'content-type': workingSet.request.headers['content-type'],
        'content-length': workingSet.request.headers['content-length'],
        'x-amz-date': workingSet.request.headers['x-amz-date'],
        // 'x-amz-content-sha256': workingSet.request.headers['x-amz-content-sha256'],
        'x-amz-security-token': this.config.sessionToken || undefined
    }
}

// Some preparations
function prepare(self, ws) {
    const headers = {
        'host': ws.uri.host,
        'content-type': self.config.defaultContentType,
        'accept': self.config.defaultAcceptType,
        'expect': self.config.defaultExpectType,
        'x-amz-date': amzDate(ws.signDate)
    }
    // Payload or not?
    ws.request.method = ws.request.method.toUpperCase()
    if (ws.request.body) {
        ws.payload = ws.request.body
    } else if (ws.request.data && self.payloadSerializer) {
        ws.payload = self.payloadSerializer(ws.request.data)
    } else {
        delete headers['content-type']
    }
    // Headers
    ws.request.headers = extend(
        headers,
        Object.keys(ws.request.headers || {}).reduce(function (normalized, key) {
            normalized[key.toLowerCase()] = ws.request.headers[key]
            return normalized
        }, {})
    )
    ws.sortedHeaderKeys = Object.keys(ws.request.headers).sort()
    // Remove content-type parameters as some browser might change them on send
    if (ws.request.headers['content-type']) {
        ws.request.headers['content-type'] = ws.request.headers['content-type'].split(';')[0]
    }
    // Merge params to query params
    if (typeof(ws.request.params) === 'object') {
        extend(ws.uri.query, ws.request.params)
    }
}

// Convert the request to a canonical format.
function buildCanonicalRequest(self, ws) {
    ws.signedHeaders = ws.sortedHeaderKeys.map(function (key) {
        return key.toLowerCase()
    }).join(';')
    ws.canonicalRequest = [
        ws.request.method.toUpperCase(),
            // Canonical URI:
        ws.uri.path.split('/').map(seg => encodeURIComponent(seg)).join('/'),
            // Canonical Query String:
        Object.keys(ws.uri.query).sort().map(function (key) {
            return encodeURIComponent(key) + '=' +
                encodeURIComponent(ws.uri.query[key])
        })
        .join('&'),
            // Canonical Headers:
        ws.sortedHeaderKeys.map(function (key) {
            return key.toLocaleLowerCase() + ':' + ws.request.headers[key]
        }).join('\n') + '\n', // extra break
            // Signed Headers:
        ws.signedHeaders,
            // Hashed Payload or 'UNSIGNED-PAYLOAD'
        (ws.request.headers['x-amz-content-sha256'] === 'UNSIGNED-PAYLOAD'
            ? 'UNSIGNED-PAYLOAD'
            : this.hasher.hash((ws.payload) ? ws.payload : ''))
    ].join('\n')
}

// Construct the string that will be signed.
function buildStringToSign(self, ws) {
    ws.credentialScope = [
        amzDate(ws.signDate, true),
        self.config.region,
        self.config.service,
        'aws4_request'
    ].join('/')
    ws.stringToSign = [
        'AWS4-HMAC-SHA256',
        amzDate(ws.signDate),
        ws.credentialScope,
        self.hasher.hash(ws.canonicalRequest)
    ].join('\n')
}

function hmac (key, input) {
    return crypto.createHmac('sha256', key).update(input).digest()
}

function sha256 (input) {
    return crypto.createHash('sha256').update(input).digest('hex')
}

// Calculate the signature
function calculateSignature(self, ws) {
    const signKey = hmac(
        hmac(
            hmac(
                hmac(
                    'AWS4' + self.config.secretAccessKey,
                    amzDate(ws.signDate, true)
                ),
                self.config.region
            ),
            self.config.service
        ),
        'aws4_request'
    )
    ws.signature = hmac(signKey, ws.stringToSign).toString('hex')
}

// Build the signature HTTP header using the data in the working set.
function buildSignatureHeader(self, ws) {
    ws.authorization = 'AWS4-HMAC-SHA256 ' +
        'Credential=' + self.config.accessKeyId + '/' + ws.credentialScope + ', ' +
        'SignedHeaders=' + ws.signedHeaders + ', ' +
        'Signature=' + ws.signature
}

// Format the given `Date` as AWS compliant date string.
// Time part gets omitted if second argument is set to `true`.
function amzDate(date, short) {
    const result = date.toISOString().replace(/[:\-]|\.\d{3}/g, '').substr(0, 17)
    if (short) {
        return result.substr(0, 8)
    }
    return result
}

// Throw an error if the given object is undefined.
function assert(statement, msg) {
    if (!statement) throw new Error(msg)
}

module.exports = {
    AwsSigner
}
