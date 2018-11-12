// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')
var urllib = require('urllib')

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://open.work.weixin.qq.com/wwopen/sso/3rd_qrConnect'
  options.scopeSeparator = options.scopeSeparator || ','
  options.customHeaders = options.customHeaders || {}
  options.tokenURL = options.tokenURL || 'https://qyapi.weixin.qq.com/cgi-bin/service/get_provider_token'
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-weixin-enterprise'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'weixin-enterprise'
  ensureToken(this._oauth2)
  this._oauth2._profileURL = options.profileURL || 'https://qyapi.weixin.qq.com/cgi-bin/service/get_login_info'
  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['appid'] = this._clientId
    params['usertype'] = options.usertype || 'member'
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    callback(null, code)
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (authCode, done) {
  urllib.request(this._oauth2._profileURL + '?access_token=' + this._oauth2.access_token, {
    method: 'POST',
    dataType: 'json',
    contentType: 'json',
    data: {
      auth_code: authCode
    }
  }, function (err, data) {
    if (err) return done(err)
    if (data.user_info && data.user_info.userid) return done(null, data)
    done(new Error('obtain user profile failed.' + (data.errmsg || '')))
  })
}

function ensureToken (oauthIns) {
  var params = {
    corpid: oauthIns._clientId,
    provider_secret: oauthIns._clientSecret
  }
  var _ensure = function () {
    urllib.request(oauthIns._getAccessTokenUrl(), {
      method: 'POST',
      dataType: 'json',
      contentType: 'json',
      data: params
    }, function (_, data) {
      if (data && data.provider_access_token) {
        oauthIns.access_token = data.provider_access_token
        if (data.expires_in) {
          setTimeout(_ensure, (data.expires_in - 10) * 1000)
        }
      } else {
        setTimeout(_ensure, 5 * 1000)
        console.warn('obtain provider_access_token failed.' + (data.errmsg || ''))
      }
    })
  }
  _ensure()
}

// Expose constructor.
module.exports = Strategy
