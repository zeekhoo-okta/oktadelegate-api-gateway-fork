"use strict";
const assert_scope = "groupadmin";

const AuthPolicy = require('aws-auth-policy');
const atob = require('atob');
const OktaJwtVerifier = require('@okta/jwt-verifier');

exports.handler = function(event, context) {
    var accessTokenString = event.authorizationToken.split(' ')[1];
    var parts = accessTokenString.split('.');
    var unverified_payload = {};

    // Custom Authorization header: Provides a way to pass in the SSWS key as part of the Authorization header. 
    // The SSWS key would be concatenated to the front of the jwt with a "."
    var ssws = false;
    if (parts.length === 3) {
        unverified_payload = JSON.parse(atob(parts[1]));
    } else {
        ssws = parts[0];
        unverified_payload = JSON.parse(atob(parts[2]));
        accessTokenString = parts.slice(1).join('.');
    }

    var oktaJwtVerifier = new OktaJwtVerifier({
      issuer: unverified_payload.iss,
      clientId: unverified_payload.cid
    });

    oktaJwtVerifier.verifyAccessToken(accessTokenString)
    .then((jwt) => {
        if (!jwt.claims.scp.includes(assert_scope)) {
            return context.fail('Unauthorized');
        }
        if (!jwt.claims.sessionid) {
            return context.fail('Unauthorized');
        }

        var apiOptions = {};
        const arnParts = event.methodArn.split(':');
        const apiGatewayArnPart = arnParts[5].split('/');
        const awsAccountId = arnParts[4];
        apiOptions.region = arnParts[3];
        apiOptions.restApiId = apiGatewayArnPart[0];
        apiOptions.stage = apiGatewayArnPart[1];

        const policy = new AuthPolicy(jwt.claims.sub, awsAccountId, apiOptions);
        policy.allowMethod(AuthPolicy.HttpVerb.POST, "/delegate/init");

        var builtPolicy = policy.build();
        var claims = jwt.claims;
        var ctx = {};
        for (var c in claims) {
            if (claims.hasOwnProperty(c)) {
                ctx[c] = JSON.stringify(claims[c]);
            }
        }
        if (ssws) {
            ctx.ssws = JSON.stringify(ssws);
        }
        builtPolicy.context = ctx;
        return context.succeed(builtPolicy);
    })
    .catch((err) => {
        console.log(err);
        return context.fail('Unauthorized');
    });
}
