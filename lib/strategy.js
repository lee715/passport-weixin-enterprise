// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var crypto = require('crypto')
var urllib = require('urllib')

function ensureToken (oauthIns) {
  var _ensure = function () {
    urllib.request('https://qyapi.weixin.qq.com/cgi-bin/service/get_provider_token', {
      data: {
        corpid: oauthIns._clientId,
        provider_secret: oauthIns._clientSecret
      },
      method: 'POST',
      dataType: 'json',
      contentType: 'json'
    }, function (err, data, res) {
      if (data && data.provider_access_token) {
        oauthIns.access_token = data.provider_access_token
        setTimeout(_ensure, data.expires_in - 10)
      } else {
        setTimeout(_ensure, 2000)
      }
    })
  }
  _ensure()
}

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://qy.weixin.qq.com/cgi-bin/loginpage'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}
  options.tokenURL = options.tokenURL || 'https://qyapi.weixin.qq.com/cgi-bin/service/get_login_info'
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-weixin-enterprise'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'weixin-enterprise'
  ensureToken(this._oauth2)
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['corp_id'] = this._clientId
    params['usertype'] = 'member'
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    callback(null, code)
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (authCode, done) {
  var self = this
  var accessToken = this._oauth2.access_token
  urllib.request(this._oauth2._accessTokenUrl + '?access_token=' + accessToken, {
    method: 'POST',
    dataType: 'json',
    contentType: 'json',
    data: {
      auth_code: authCode
    }
  }, function (err, data, res) {
    if (!data || !data.user_info || !data.user_info.userid) return done(new Error('invalidUserProfile'))
    urllib.request('https://qyapi.weixin.qq.com/cgi-bin/user/convert_to_openid?access_token=' + accessToken, {
      method: 'POST',
      data: {
        userid: data.user_info.userid
      },
      dataType: 'json',
      contentType: 'json'
    }, function (err, rt) {
      if (err || rt.errcode) return done(new Error('convertOpenIdError'))
      data.openid = rt.openid
      done(null, data)
    })
  })
}

// Expose constructor.
module.exports = Strategy
