var jwt = require('express-jwt');
var secret = require('../config').secret;

function getTokenFromHeader(req) { // extract jwt from the authorization header
	if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Token') {
		return req.headers.authorization.split(' ')[1];
	}
	return null;
}

var auth = {
	required: jwt({ // Authentication required
		secret: secret,
		userProperty: 'payload',
		getToken: getTokenFromHeader
	}),
	optional: jwt({ // Authentication optional
		secret: secret,
		userProperty: 'payload',
		credentialsRequired: false,
		getToken: getTokenFromHeader
	})
};

module.exports = auth;



