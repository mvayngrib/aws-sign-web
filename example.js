require('isomorphic-fetch')

const { Readable } = require('stream')
const awsSignWeb = require('./aws-sign-web')

const config = {
  "accessKeyId": "ASIAIGWAG36HTKVJEGJA",
  "secretAccessKey": "rtLEpqnzhS67axD9Zy6t6woK62L+0cVmxt3I0mgk",
  "sessionToken": "FQoDYXdzEOX//////////wEaDFABJ8YfCq8hdY6s+SLjAfDKMjkiilgJWLtA11E3o6juiemfuh3tIofSuttqC/lgAu5rb6sS4mAOZ4cVWhfvJGPfoYse47SEy64js02dxzlaIV+TpUnYVufKmCX9J/uA3+iRYMGvN9T51e4KLjNTECCWg6w3WY0eLsmM+eICobnSBXytG8aem0sbNJ156NLEqNZj2jGj7Jfgr/UgwmjgAMqHdXY+Afb4LtePwf2RW1dp37EnAFRVot2gYQjUDS9p/Y33eprJzj1DAqo9uw9fNnxnjeER1ufwL6ohFTZCS68vO5Z8EygdV+nEtwJzcwFsweIEKOat3c0F"
}

config.region = 'us-east-1'
config.service = 's3'

const signer = new awsSignWeb.AwsSigner(config)
const data = new Buffer('ffc8ffe000104a46494600010100000100010000', 'hex')
const path = "/AROAJHWM4CI3ALHOZHDJS:775759308c577ce158d828bd24dae631/ffd81ef52c22fd853b1db477ceec2a735ef4875a17e18daa8d48a7ce1040c398"
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
