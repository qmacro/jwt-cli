#! /usr/bin/env node

var colors = require('colors/safe');
var json = require('format-json');
var jwt = require('jsonwebtoken');

const commandLineArgs = require('command-line-args');
const options = commandLineArgs([
  { name: 'url',       alias: 'u', type: Boolean },
  { name: 'header',    alias: 'h', type: Boolean },
  { name: 'payload',   alias: 'p', type: Boolean },
  { name: 'validity',  alias: 'v', type: Boolean },
  { name: 'signature', alias: 'i', type: Boolean },
  { name: 'raw',       alias: 'r', type: Boolean },
  { name: 'secret',    alias: 's', type: String },
  { name: 'token',     alias: 't', type: String, defaultOption: true }
], { partial: true} );

// Set special 'all' if no section options were specified
options.all = ! ['url', 'header', 'payload', 'validity', 'signature'].some(x => options.hasOwnProperty(x))
options.cooked = options.all || ! options.raw

const color = (data, color) => color ? colors[color](data) : data

function niceDate(unixTimestamp) {
  var dateString;
  if (typeof unixTimestamp === 'number' && !isNaN(unixTimestamp)) {
    dateString = new Date(unixTimestamp * 1000).toLocaleString();
  } else {
    dateString = 'Invalid Date';
  }
  return colors.yellow(unixTimestamp) + ' ' + dateString;
}

function processToken(token) {
  if (token.string === undefined || token.string.split('.').length !== 3) {
    const pkg = require('../package.json');
    console.log(`jwt-cli - JSON Web Token parser [version ${pkg.version}]\n`);
    console.info(
      colors.yellow('Usage: jwt <encoded token> --secret=<signing secret> [--verifyurl] [--header] [--payload] [--validity] [--signature] [--raw]\n')
    );
    console.log('ℹ Documentation: https://www.npmjs.com/package/jwt-cli');
    console.log(
      '⚠ Issue tracker: https://github.com/troyharvey/jwt-cli/issues'
    );
    return;
  }

  token.parts = token.string.split('.');
  token.decoded = jwt.decode(token.string, { complete: true });

  if (token.decoded === null) {
    console.log('\n😾  token no good');
    return false;
  }

  if (options.all || options.url) {
    console.log(colors.yellow('\nTo verify on jwt.io:'));
    console.log(
      '\n' +
        colors.magenta('https://jwt.io/#id_token=') +
        colors.cyan(token.parts[0]) +
        '.' +
        colors.yellow(token.parts[1]) +
        '.' +
        colors.magenta(token.parts[2])
    );
  }

  if (options.all || options.header) {
    options.cooked && console.log(colors.cyan('\n✻ Header'));
    console.log(color(json.plain(token.decoded.header), options.cooked && 'cyan'));
  }

  if (options.all || options.payload) {
    options.cooked && console.log(colors.yellow('\n✻ Payload'));
    console.log(color(json.plain(token.decoded.payload), options.cooked && 'yellow'));
  }

  if (options.all || options.validity) {
    const dates = { iat: 'Issued At', nbf: 'Not Before', exp: 'Expiration Time' };
    for (const [field, name] of Object.entries(dates)) {
      if (Object.prototype.hasOwnProperty.call(token.decoded.payload, field)) {
        console.log(
          colors.yellow(`   ${name}: `) + niceDate(token.decoded.payload[field])
        );
      }
    }
  }

  if (options.all || options.signature) {
    options.cooked && console.log(colors.magenta('\n✻ Signature '));
    console.log(token.decoded.signature);
  }
  return true;
}

function verifyToken(token, secret) {
  try {
    jwt.verify(token.string, secret);
    console.log(colors.green('\n✻ Signature Verified!'));
  } catch (err) {
    console.log(colors.red('\n✻ Invalid Signature!'));
  }
}

function handleTokenAsAnArg() {
  token.string = options.token;
  token.isValid = processToken(token);
  if (token.isValid && options.secret) {
    verifyToken(token, options.secret);
  }
}

function handleTokenAsStdin() {
  var data = '';
  process.stdin.on('readable', function () {
    var chunk;
    while ((chunk = process.stdin.read())) {
      data += chunk;
    }
  });

  process.stdin.on('end', function () {
    // There will be a trailing \n from the user hitting enter. Get rid of it.
    data = data.replace(/\n$/, '');
    token.string = data;
    processToken(token);
  });
}

var token = {};

if (process.stdin.isTTY) {
  handleTokenAsAnArg();
} else {
  handleTokenAsStdin();
}
