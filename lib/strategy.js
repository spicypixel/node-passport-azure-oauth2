/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2');

/**
 * `Strategy` constructor.
 *
 * The Azure authentication strategy authenticates requests by delegating to
 * Active Directory using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Azure application's App ID
 *   - `clientSecret`  your Azure application's App Secret
 *   - `callbackURL`   URL to which Azure will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new AzureStrategy({
 *         tenantID: '12c983bf-46f6-414f-93ab-5d7ad211db43'
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/azure/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://login.windows.net/' + options.tenantID + '/oauth2/authorize?api-version=1.0';
  options.tokenURL = options.tokenURL || 'https://login.windows.net/' + options.tenantID + '/oauth2/token?api-version=1.0';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'azure';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to Azure using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Return extra parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};

  // [Optional] Provides a hint about the tenant or domain that the user
  // should use to sign in. The value of the domain_hint is a registered domain
  // for the tenant. If the tenant is federated to an on-premises directory, AAD
  // redirects to the specified tenant federation server.
  if(options.domain_hint)
    params.domain_hint = options.domain_hint;

  // [Optional] Provides a hint to the user on the sign-in page. For example,
  // this value is pre-filled in the username field on the sign-in page.
  if(options.login_hint)
    params.login_hint = options.login_hint;

  // [Optional] Indicate the type of user interaction that is required.
  // Valid values are:
  // -- login: The user should be prompted to re-authenticate.
  // -- consent: User consent has been granted, but needs to be updated. The
  // user should be prompted to consent.
  // -- admin_consent: An administrator should be prompted to consent on behalf
  // of all users in their organization.
  if(options.prompt)
    params.prompt = options.prompt;

  // [Optional] The App ID URI of the web API (secured resource).
  // To find the App ID URI of the web API, in the Azure Management Portal,
  // click Active Directory, click the directory, click the application and then
  // click Configure.
  if(options.resource)
    params.resource = options.resource;

  return params;
};

/**
 * Return extra parameters to be included in the token request.
 *
 * @return {Object}
 * @api protected
 */
Strategy.prototype.tokenParams = function(options) {
  var params = {};

  // [Optional] The App ID URI of the web API (secured resource).
  // To find the App ID URI of the web API, in the Azure Management Portal,
  // click Active Directory, click the directory, click the application and then
  // click Configure.
  if(options.resource)
    params.resource = options.resource;

  return params;
};

/**
 * Retrieve user profile from Azure.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `azure`
 *   - `id`               the user's Active Directory oid
 *   - `orgId`            the user's Active Directory tid
 *   - `username`         the user's Active Directory unique_name
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var profile = { provider : this.name };

  // get what info we can from the base64 encoded bearer token
  try {
    var tokenBase64 = accessToken.split('.')[1];
    var tokenBinary = new Buffer(tokenBase64, 'base64');
    var tokenUTF8 = tokenBinary.toString('utf-8');
    profile.utf8 = tokenUTF8;
    var tokenJson = JSON.parse(tokenUTF8);
    profile.json = tokenJson;
    profile.id = tokenJson.oid;
    profile.orgId = tokenJson.tid;
    profile.username = tokenJson.unique_name;
    profile.displayname = tokenJson.given_name + ' ' + tokenJson.family_name;
    profile.name = {
      familyName: tokenJson.family_name,
      givenName: tokenJson.given_name
    };
    profile.emails = [tokenJson.email];
    done(null, profile);
  } catch(exception) {
    console.log("Unable to parse oauth2 token for user profile");
    done(ex, null);
  }
};

/**
 * Parse error response from Facebook OAuth 2.0 token endpoint.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
Strategy.prototype.parseErrorResponse = function(body, status) {
  return OAuth2Strategy.prototype.parseErrorResponse.call(this, body, status);
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
