var http = require('http')
  , fs = require('fs')
  , browserify = require('browserify')

var html = [
  '<!DOCTYPE html>',
  '<meta charset="utf-8">',
  '<link rel="stylesheet" href="mocha.css" />',
  '<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>',
  '<script src="mocha.js"></script>',
  '<script src="terst.js"></script>',
  '<script src="bip38.js"></script>',
  '<script>mocha.setup("bdd")</script>',
  '<script src="bip38.test.js"></script>',
  '<script>$(function () { mocha.run().globals(["mod"]) });</script>',
  '<div id="mocha"></div>'
].join('\n')

var server = http.createServer(function(req, res) {
  switch (req.url) {
    case '/':
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(html); break;
    case '/mocha.js':
      res.writeHead(200, {'Content-Type': 'application/javascript'});
      fs.createReadStream('./node_modules/mocha/mocha.js').pipe(res); break;
    case '/terst.js':
      res.writeHead(200, {'Content-Type': 'application/javascript'});
      fs.createReadStream('./node_modules/terst/lib/terst.js').pipe(res); break;
    case '/mocha.css':
      res.writeHead(200, {'Content-Type': 'text/css'});
      fs.createReadStream('./node_modules/mocha/mocha.css').pipe(res); break;
    case '/bip38.js':
      res.writeHead(200, {'Content-Type': 'application/javascript'});
      browserify('./lib/bip38.js').bundle({debug: true, standalone: 'mod'}).pipe(res); break;  
    case '/bip38.test.js':
      res.writeHead(200, {'Content-Type': 'application/javascript'});
      fs.createReadStream('./test/bip38.test.js').pipe(res); break;
    default:
      res.writeHead(404, {'Content-Type': 'text/plain'});
      res.end(req.url + ' not found.');
  }
});

server.listen(8080, function() {
  console.log('\n  listening on port 8080...\n');
});