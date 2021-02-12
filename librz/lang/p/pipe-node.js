#!/usr/bin/node
// $ rizin -qc '#!pipe node pipe-node.js' -

var isMain = process.argv[1] == __filename;

var fs = require("fs");

function langPipe() {
  var IN = +process.env.RZ_PIPE_IN;
  var OUT = +process.env.RZ_PIPE_OUT;

  var rzio = {
    r: fs.createReadStream(null, { fd: IN }),
    w: fs.createWriteStream(null, { fd: OUT }),
  };

  var replies = [];
  rzio.cmd = function (cmd, cb) {
    replies.push(cb);
    rzio.w.write(cmd);
  };
  rzio.r.on("data", function (foo) {
    if (replies.length > 0) {
      var cb = replies[0];
      replies = replies.slice(1);
      if (cb) cb("" + foo);
    }
  });

  rzio.repl = function () {
    /* rizin repl implemented in pipe-node.js */
    rzio.r.pipe(process.stdout);
    process.stdin.on("data", function (chunk) {
      if (replies.length > 0) {
        var cb = replies[0];
        replies = replies.slice(1);
        var cb = replies.pop();
        if (cb) cb("" + chunk);
      }
      rzio.w.write(chunk);
    });
  };
  return rzio;
}

// Example:
if (isMain) {
  var lp = langPipe();
  lp.cmd("pd 3", function (x) {
    console.log(x);
    lp.cmd("px 64", function (y) {
      console.log(y);
      lp.repl();
    });
  });
} else {
  module.exports = langPipe();
}
