require('isomorphic-fetch')

const { Readable } = require('stream')
const awsSignWeb = require('./aws-sign-web')

const config = {
  "accessKeyId": "ASIAJRLOM7HIKLXOXVPQ",
  "secretAccessKey": "rdY4YWZ2Qn5A9zsc0s595mS/0Hq2FKjK8zpIjQYa",
  "sessionToken": "FQoDYXdzEOX//////////wEaDKBRQVhoYyYcJZlWmCLjAc2ONhoaoKTqvEx7Z4aNE/B2+SzMJNLUC2qRYPKsxRI1qgw9U4llybUA2SfNUM2hVXShlGPamjT/HaubWjGyFLCMpiRmVPl5rlEgE0JzyW5eFdy6cE9OjVyb3OsKstb0+S68UHe+aCwsJ88fvaB+ma/hdSzkkD8tvxJaYvBhr+Ew8bPztuOjnPHv/rbtRIczaglS2wTz/bi5UgPsxzFkuq5nV8i+qlArkclGwokNqmroGzcNGCpmczathvnQlMk5q3nzUgMBMXlLfhnQw9jRydiqCkqkWeRcSRpwc+bBpOHyLlSfKIqz3c0F"
}

// const userId =

config.region = 'us-east-1'
config.service = 's3'

const signer = new awsSignWeb.AwsSigner(config)
const data = new Buffer('ffc8ffe000104a46494600010100000100010000', 'hex')
const path = "/AROAJHWM4CI3ALHOZHDJS:a05d1b9bb014e129fa0a489014d1b5aa/ffd81ef52c22fd853b1db477ceec2a735ef4875a17e18daa8d48a7ce1040c398"
const url = 'https://tradle-dev-fileuploadbucket-nuwmqnmh0phg.s3.amazonaws.com' + path
const request = {
  method: 'PUT',
  url,
  headers: {
    "expect": '100-continue',
    "Content-Type": "image/jpeg",
    "Content-Length": 20,
    "Host": "tradle-dev-fileuploadbucket-nuwmqnmh0phg.s3.amazonaws.com",
    "x-amz-content-sha256": 'UNSIGNED-PAYLOAD',
    "x-amz-security-token": config.sessionToken,
  },
  body: data
}

request.headers = signer.sign(request)
request.headers['x-amz-content-sha256'] = 'UNSIGNED-PAYLOAD'
request.headers.expect = '100-continue'
console.log(request)

delete request.url
request.body = data
fetch(url, request)
  .then(res => res.text())
  .then(console.log, console.error)
