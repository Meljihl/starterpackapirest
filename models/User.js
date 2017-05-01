var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');

var secret = require('../config').secret;

var UserSchema = new mongoose.Schema( {
    username: {type: String, lowercase: true, unique: true, required: [true, "can't be empty"], match: [/^[a-zA-Z0-9]+$/, 'is invalid'], index: true}, // index true to optimize request
    email: {type: String, lowercase: true, unique: true, required: [true, "can't be empty"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true},
    bio: String,
    image: String,
    hash: String,
    salt: String
}, {timestamps: true}); // create a createdAt and updatedAt field which contains timestamps

UserSchema.plugin(uniqueValidator, {message: 'Already taken'});


UserSchema.methods.setPassword = function(password) {
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex'); // password, salt, number of times to hash, length of the hash, algorithm used
};

UserSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
    return this.hash === hash;
};

UserSchema.methods.generateJWT = function() {
    var today = new Date();
    var exp = new Date(today);

    exp.setDate((today.getDate()) + 60); // 60 days validity

    return jwt.sign({
        id: this._id, // Database id of the user
        username: this.username, // username of the user
        exp: parseInt(exp.getTime() / 1000) // timestamp determining when the token expire
    }, secret);
};

UserSchema.methods.toAuthJson = function() {
    return {
        username: this.username,
        email: this.email,
        token: this.generateJWT()
    };
};

UserSchema.methods.toProfileJSONFor = function(user) {
	return {
		username: this.username,
		bio: this.bio,
		image: this.image || 'https://static.productionready.io/images/smiley-cyrus.jpg', // If the user has no img, we prefer url then null
		following: false
	}
};



mongoose.model('User', UserSchema); // register schema, can be accessed anywhere by calling mongoose.model('User')